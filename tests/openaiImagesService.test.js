const { Readable } = require('stream')
const FormData = require('form-data')

jest.mock('../config/config', () => ({ requestTimeout: 600000 }), { virtual: true })
jest.mock('../src/utils/proxyHelper', () => ({ createProxyAgent: jest.fn(() => null) }))
jest.mock('axios', () => jest.fn())

const axios = require('axios')
const {
  parseImagesRequest,
  buildDirectTargetUrl,
  buildCodexImagesRequest,
  collectCodexImageStream,
  forwardDirectImages,
  buildImagesResponse
} = require('../src/services/openaiImagesService')

describe('openaiImagesService', () => {
  test('builds direct Images URLs without duplicating /v1', () => {
    expect(buildDirectTargetUrl('https://api.openai.com', '/v1/images/generations')).toBe(
      'https://api.openai.com/v1/images/generations'
    )
    expect(buildDirectTargetUrl('https://example.com/v1', '/v1/images/edits')).toBe(
      'https://example.com/v1/images/edits'
    )
  })

  test('parses a JSON generation request and applies defaults', async () => {
    const parsed = await parseImagesRequest({
      headers: { 'content-type': 'application/json' },
      path: '/v1/images/generations',
      body: { prompt: 'draw a relay logo' }
    })

    expect(parsed).toMatchObject({
      endpoint: '/v1/images/generations',
      model: 'gpt-image-2',
      prompt: 'draw a relay logo',
      n: 1,
      multipart: false,
      responseFormat: 'b64_json'
    })
  })

  test('parses multipart edits and converts uploaded images for Codex', async () => {
    const form = new FormData()
    form.append('model', 'gpt-image-2')
    form.append('prompt', 'remove the background')
    form.append('quality', 'medium')
    form.append('image', Buffer.from('image-bytes'), {
      filename: 'input.png',
      contentType: 'image/png'
    })
    form.append('mask', Buffer.from('mask-bytes'), {
      filename: 'mask.png',
      contentType: 'image/png'
    })

    const req = Readable.from([form.getBuffer()])
    req.headers = form.getHeaders()
    req.path = '/v1/images/edits'
    const parsed = await parseImagesRequest(req)
    const payload = buildCodexImagesRequest(parsed)

    expect(parsed.imageFiles).toHaveLength(1)
    expect(parsed.maskFile.filename).toBe('mask.png')
    expect(payload.tools[0]).toMatchObject({
      type: 'image_generation',
      action: 'edit',
      model: 'gpt-image-2',
      quality: 'medium'
    })
    expect(payload.model).toBe('gpt-5.4-mini')
    expect(payload.input[0].content[1].image_url).toBe(
      `data:image/png;base64,${Buffer.from('image-bytes').toString('base64')}`
    )
    expect(payload.tools[0].input_image_mask.image_url).toBe(
      `data:image/png;base64,${Buffer.from('mask-bytes').toString('base64')}`
    )

    axios.mockResolvedValueOnce({ status: 200, data: Buffer.from('{}'), headers: {} })
    await forwardDirectImages(
      { headers: { 'user-agent': 'test-client' } },
      parsed,
      { baseApi: 'https://images.example/v1', apiKey: 'upstream-key' },
      null
    )
    const directRequest = axios.mock.calls[0][0]
    expect(directRequest.url).toBe('https://images.example/v1/images/edits')
    expect(directRequest.headers.Authorization).toBe('Bearer upstream-key')
    expect(directRequest.headers['content-type']).toMatch(/^multipart\/form-data; boundary=/)
    expect(directRequest.data).toBeInstanceOf(FormData)
  })

  test('extracts image results and usage from Codex SSE', async () => {
    const stream = Readable.from([
      'data: {"type":"response.image_generation_call.partial_image","partial_image_b64":"cGFydA==","partial_image_index":0,"output_format":"png"}\n\n',
      'data: {"type":"response.output_item.done","item":{"type":"image_generation_call","result":"aW1hZ2U=","output_format":"png"}}\n\n',
      'data: {"type":"response.completed","response":{"created_at":1780000000,"model":"gpt-5.4","usage":{"input_tokens":2,"output_tokens":3,"total_tokens":5},"tool_usage":{"image_gen":{"input_tokens":46,"output_tokens":2459,"output_tokens_details":{"image_tokens":2459}}},"output":[{"type":"image_generation_call","result":"aW1hZ2U=","output_format":"png"}]}}\n\n'
    ])
    const events = []

    const state = await collectCodexImageStream(stream, (event) => events.push(event))

    expect(state.results).toEqual([{ result: 'aW1hZ2U=', revisedPrompt: '', outputFormat: 'png' }])
    expect(state.usage.output_tokens).toBe(2459)
    expect(events.map((event) => event.type)).toEqual(['partial', 'completed'])
    expect(events[1].usage.output_tokens_details.image_tokens).toBe(2459)
    expect(buildImagesResponse(state, 'b64_json')).toEqual({
      created: 1780000000,
      data: [{ b64_json: 'aW1hZ2U=' }],
      usage: {
        input_tokens: 46,
        output_tokens: 2459,
        output_tokens_details: { image_tokens: 2459 }
      }
    })
  })
})
