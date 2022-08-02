package nsign

import (
	"bytes"
	"sync"
)

type Buffer struct {
	*bytes.Buffer
	p *sync.Pool
}

func NewBuffer() *Buffer {
	var b = &Buffer{}
	b.Buffer = bytes.NewBufferString("")
	return b
}

func (this *Buffer) Reset() {
	this.Buffer.Reset()
}

func (this *Buffer) Release() {
	this.Reset()
	this.p.Put(this)
	this.p = nil
}

type BufferPool struct {
	bPool *sync.Pool
}

func NewBufferPool() *BufferPool {
	var b = &BufferPool{}
	b.bPool = &sync.Pool{
		New: func() interface{} {
			return NewBuffer()
		},
	}
	return b
}

func (this *BufferPool) GetBuffer() *Buffer {
	var b = this.bPool.Get().(*Buffer)
	b.Reset()
	b.p = this.bPool
	return b
}
