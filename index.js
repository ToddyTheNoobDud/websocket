const https = require('node:https')
const http = require('node:http')
const crypto = require('node:crypto')
const { EventEmitter } = require('node:events')
const { URL } = require('node:url')
const { Buffer } = require('node:buffer')

let nativeWs = null
if (process.isBun) nativeWs = require('ws')

const _parseFrameHeader = (buffer) => {
  let startIndex = 2

  const opcode = buffer[0] & 15
  const fin = (buffer[0] & 128) === 128
  let payloadLength = buffer[1] & 127

  let mask = null
  if ((buffer[1] & 128) === 128) {
    mask = buffer.subarray(startIndex, startIndex + 4)
    startIndex += 4
  }

  if (payloadLength === 126) {
    payloadLength = buffer.readUInt16BE(2)
    startIndex += 2
  } else if (payloadLength === 127) {
    payloadLength = buffer.readUIntBE(2, 6)
    startIndex += 8
  }

  // Make sure we don't read beyond the buffer length
  const availableData = buffer.length - startIndex
  const actualPayloadLength = Math.min(payloadLength, availableData)
  
  // Extract payload data
  const payload = buffer.subarray(startIndex, startIndex + actualPayloadLength)

  // If masked, unmask the payload
  if (mask) {
    for (let i = 0; i < actualPayloadLength; i++) {
      payload[i] ^= mask[i & 3]
    }
  }

  return {
    opcode,
    fin,
    buffer: payload,
    payloadLength,
    frameLength: startIndex + actualPayloadLength,
    actualPayloadLength
  }
}

class WebSocket extends EventEmitter {
  constructor(url, options) {
    super()
    this.url = url
    this.options = options
    this.socket = null
    this.continueInfo = {
      type: -1,
      buffer: []
    }
    this.dataBuffer = Buffer.alloc(0)

    this.connect()
  }

  connect() {
    const parsedUrl = new URL(this.url)
    const isSecure = parsedUrl.protocol === 'wss:'
    const agent = isSecure ? https : http
    const key = crypto.randomBytes(16).toString('base64')

    const request = agent.request({
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (isSecure ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      timeout: this.options?.timeout ?? 30000,
      headers: {
        'Sec-WebSocket-Key': key,
        'Sec-WebSocket-Version': 13,
        'Upgrade': 'websocket',
        'Connection': 'Upgrade',
        ...(this.options?.headers || {})
      },
      method: 'GET'
    });

    request.on('error', (err) => {
      this.emit('error', err)
      this.emit('close')
      this.cleanup()
    })

    request.on('upgrade', (res, socket, head) => {
      socket.setNoDelay()
      socket.setKeepAlive(true)

      if (head.length !== 0) socket.unshift(head)

      if (res.headers.upgrade.toLowerCase() !== 'websocket') {
        socket.destroy()
        return;
      }

      const digest = crypto.createHash('sha1')
        .update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
        .digest('base64')

      if (res.headers['sec-websocket-accept'] !== digest) {
        socket.destroy()
        return;
      }

      socket.on('data', (data) => {
        // Append new data to our buffer
        this.dataBuffer = Buffer.concat([this.dataBuffer, data])
        
        // Process all complete frames in the buffer
        this.processBuffer()
      })

      socket.on('close', () => {
        this.emit('close', 1006, null)
        this.cleanup()
      })

      socket.on('error', (err) => {
        this.emit('error', err)
        this.emit('close', 1006, null)
        this.cleanup()
      })

      this.socket = socket
      this.emit('open', socket, res.headers)
    })

    request.end()
  }

  processBuffer() {
    // Process as many frames as we can from the buffer
    while (this.dataBuffer.length >= 2) {
      // Check if we have enough data for the frame header
      const payloadLength = this.dataBuffer[1] & 127
      let headerLength = 2 + (this.dataBuffer[1] & 128 ? 4 : 0) // Base + mask
      
      if (payloadLength === 126) {
        headerLength += 2
      } else if (payloadLength === 127) {
        headerLength += 8
      }
      
      // Not enough data for the complete header yet
      if (this.dataBuffer.length < headerLength) {
        break
      }
      
      // Parse the frame header
      const headers = _parseFrameHeader(this.dataBuffer)
      
      // Check if we have the complete frame
      if (this.dataBuffer.length < headers.frameLength) {
        // Not enough data for the complete frame, wait for more
        break
      }
      
      // Process the frame
      this.handleFrame(headers)
      
      // Remove the processed frame from the buffer
      this.dataBuffer = this.dataBuffer.subarray(headers.frameLength)
    }
  }

  handleFrame(headers) {
    switch (headers.opcode) {
      case 0x0: { // Continuation frame
        if (this.continueInfo.type === -1) {
          this.close(1002, 'Received continuation frame with no initial frame')
          return;
        }
        
        this.continueInfo.buffer.push(headers.buffer)

        if (headers.fin) {
          const data = this.continueInfo.type === 1 
            ? Buffer.concat(this.continueInfo.buffer).toString('utf8')
            : Buffer.concat(this.continueInfo.buffer)
          
          this.emit('message', data)
          this.continueInfo = { type: -1, buffer: [] }
        }
        break
      }
      case 0x1: // Text frame
      case 0x2: { // Binary frame
        if (this.continueInfo.type !== -1) {
          this.close(1002, 'Received new frame while waiting for continuation')
          return;
        }

        if (!headers.fin) {
          this.continueInfo.type = headers.opcode
          this.continueInfo.buffer.push(headers.buffer)
        } else {
          // Complete non-fragmented message
          const data = headers.opcode === 0x1 
            ? headers.buffer.toString('utf8') 
            : headers.buffer
          
          this.emit('message', data)
        }
        break
      }
      case 0x8: { // Close frame
        if (headers.buffer.length >= 2) {
          const code = headers.buffer.readUInt16BE(0)
          const reason = headers.buffer.length > 2 
            ? headers.buffer.subarray(2).toString('utf-8') 
            : ''
          this.emit('close', code, reason)
        } else {
          this.emit('close', 1006, '')
        }
        this.cleanup()
        break
      }
      case 0x9: { // Ping frame
        // Send a pong with the same payload
        const pong = Buffer.allocUnsafe(2 + headers.buffer.length)
        pong[0] = 0x8A // Fin + Pong opcode
        pong[1] = headers.buffer.length
        
        if (headers.buffer.length > 0) {
          headers.buffer.copy(pong, 2)
        }
        
        if (this.socket) this.socket.write(pong)
        this.emit('ping', headers.buffer)
        break
      }
      case 0xA: { // Pong frame
        this.emit('pong', headers.buffer)
        break
      }
    }
  }

  cleanup() {
    if (this.socket) {
      this.socket.destroy()
      this.socket = null
    }
    this.continueInfo = { type: -1, buffer: [] }
    this.dataBuffer = Buffer.alloc(0)
  }

  sendData(data, options) {
    if (!this.socket || this.socket.destroyed) {
      this.emit('error', new Error('WebSocket is not connected'))
      return;
    }

    let payloadStartIndex = 2
    let payloadLength = options.len
    let mask = null

    if (options.mask) {
      mask = Buffer.allocUnsafe(4)
      while ((mask[0] | mask[1] | mask[2] | mask[3]) === 0)
        crypto.randomFillSync(mask, 0, 4)
      payloadStartIndex += 4
    }

    if (options.len >= 65536) {
      payloadStartIndex += 8
      payloadLength = 127
    } else if (options.len > 125) {
      payloadStartIndex += 2
      payloadLength = 126
    }

    const header = Buffer.allocUnsafe(payloadStartIndex)
    header[0] = options.fin ? options.opcode | 128 : options.opcode
    header[1] = payloadLength

    if (payloadLength === 126) {
      header.writeUInt16BE(options.len, 2)
    } else if (payloadLength === 127) {
      header.writeUIntBE(options.len, 2, 6)
    }

    if (options.mask) {
      header[1] |= 128
      header[payloadStartIndex - 4] = mask[0]
      header[payloadStartIndex - 3] = mask[1]
      header[payloadStartIndex - 2] = mask[2]
      header[payloadStartIndex - 1] = mask[3]

      // Create a copy of the data to avoid modifying the original
      const maskedData = Buffer.from(data)
      for (let i = 0; i < options.len; i++) {
        maskedData[i] ^= mask[i & 3]
      }
      data = maskedData
    }

    if (this.socket && !this.socket.destroyed) {
      this.socket.write(Buffer.concat([header, data]))
    }
  }

  send(data) {
    if (typeof data === 'string') {
      const payload = Buffer.from(data, 'utf-8')
      this.sendData(payload, { len: payload.length, fin: true, opcode: 0x01, mask: true })
    } else if (Buffer.isBuffer(data)) {
      this.sendData(data, { len: data.length, fin: true, opcode: 0x02, mask: true })
    } else {
      throw new Error('Data must be a string or Buffer')
    }
  }

  ping(data = '') {
    const payload = typeof data === 'string' ? Buffer.from(data, 'utf-8') : data
    this.sendData(payload, { len: payload.length, fin: true, opcode: 0x09, mask: true })
  }

  close(code = 1000, reason = 'normal close') {
    if (!this.socket || this.socket.destroyed) return;
    
    const reasonBuffer = Buffer.from(reason, 'utf-8')
    const data = Buffer.allocUnsafe(2 + reasonBuffer.length)
    data.writeUInt16BE(code)
    reasonBuffer.copy(data, 2)
    
    this.sendData(data, { len: data.length, fin: true, opcode: 0x08, mask: true })
    
    // Give the socket some time to send the close frame before destroying it
    setTimeout(() => this.cleanup(), 100)
  }
}

module.exports = nativeWs || WebSocket
