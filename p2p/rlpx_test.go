// Copyright 2020 YOUCHAIN FOUNDATION LTD.
// This file is part of the go-youchain library.
//
// The go-youchain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-youchain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-youchain library. If not, see <http://www.gnu.org/licenses/>.

package p2p

import (
	"bytes"
	"fmt"
	"github.com/youchainhq/go-youchain/rlp"
	"testing"
)

func Test_DECode(t *testing.T) {

	data := "test decode"
	size, r, err := rlp.EncodeToReader(data)
	if err != nil {
		panic(err)
	}

	msg := Msg{
		Code:    0x09,
		Size:    uint32(size),
		Payload: r,
	}

	buf, err := Encode(msg)
	if err != nil {
		panic(err)
	}

	bufread := bytes.NewReader(buf)

	nmsg, err := Decode(bufread)
	if err != nil {
		panic(err)
	}

	t.Logf("msg: %v", nmsg)
}

func Benchmark_Encdoe(b *testing.B) {

	for i := 0; i < b.N; i++ {
		base := "test 0x6953eb0e8aac7b8f499ecbe7dab7b8b384324441325a70bcbe39d36481b0243e0x6953eb0e8aac7b8f499ecbe7dab7b8b384324441325a70bcbe39d36481b0243e0x465b1fecb3423c350b842f81bedc1c2000a531388775149fb429bb0e76b613860x6953eb0e8aac7b8f499ecbe7dab7b8b384324441325a70bcbe39d36481b0243e0x6953eb0e8aac7b8f499ecbe7dab7b8b384324441325a70bcbe39d36481b0243e0x6953eb0e8aac7b8f499ecbe7dab7b8b384324441325a70bcbe39d36481b0243e0x465b1fecb3423c350b842f81bedc1c2000a531388775149fb429bb0e76b613860x6953eb0e8aac7b8f499ecbe7dab7b8b384324441325a70bcbe39d36481b0243e"

		data := fmt.Sprintf("%x%x%x%d", base, base, base, i)

		size, r, err := rlp.EncodeToReader(data)
		if err != nil {
			panic(err)
		}

		b.Logf("payload size %d", size)

		msg := Msg{
			Code:    0x09,
			Size:    uint32(size),
			Payload: r,
		}

		_, err = Encode(msg)

		if err != nil {
			b.Logf("%d failed", i)
		}
	}
}
