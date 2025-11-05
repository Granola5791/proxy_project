package main

type BitMap struct{
	Bitmap uint64
}

func NewBitMap() *BitMap {
	return &BitMap{Bitmap: 0}
}

func (b *BitMap) SetBitOn(index int) {
	b.Bitmap |= 1 << index
}

func (b *BitMap) SetBitOff(index int) {
	b.Bitmap &= ^(1 << index)
}

func (b *BitMap) GetBit(index int) bool {
	return (b.Bitmap & (1 << index)) != 0
}

func (b *BitMap) ToggleBit(index int) {
	b.Bitmap ^= 1 << index
}

func (b *BitMap) Clear() {
	b.Bitmap = 0
}

func (b *BitMap) IsEmpty() bool {
	return b.Bitmap == 0
}