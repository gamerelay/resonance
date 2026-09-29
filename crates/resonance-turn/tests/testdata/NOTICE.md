# Test data from other projects

Real browser traffic, kept byte for byte:

| File | From | License |
|---|---|---|
| `01_chromeallocreq.hex` | [pion/turn](https://github.com/pion/turn) `internal/proto/testdata` at `ee2b969`: Chrome's unauthenticated Allocate, coturn's 401, Chrome's authenticated Allocate, the success. | MIT, Copyright (c) 2026 The Pion community |
| `02_chandata.hex` | pion/turn, same place: two ChannelData frames from Chrome (an ICE check, and an unpadded 547-byte DTLS flight). | MIT, Copyright (c) 2026 The Pion community |
| `frombrowsers.csv` | [pion/stun](https://github.com/pion/stun) `testdata` at `1b0303d`: Binding requests from Chrome and Firefox. | CC0-1.0 |

pion/turn's MIT license:

> MIT License
> 
> Copyright (c) 2026 The Pion community <https://pion.ly>
> 
> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
> 
> The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
> 
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
