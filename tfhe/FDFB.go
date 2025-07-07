package tfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/vec"
)

func (e *Evaluator[T]) GenCompressLUTAssign(lutOut LookUpTable[T]) {
	baseMessageModulus := e.Parameters.messageModulus
	polyDegree := 2048
	lutRaw := make([]T, polyDegree)
	for x := T(0); x < baseMessageModulus/2; x++ {
		start := num.DivRound(2*int(x)*polyDegree, int(baseMessageModulus))
		end := num.DivRound(2*(int(x)+1)*polyDegree, int(baseMessageModulus))
		for xx := start; xx < end; xx++ {
			lutRaw[xx] = (T(1)<<63/baseMessageModulus)*x + (T(1) << 62 / baseMessageModulus)
		}
	}

	offset := num.DivRound(polyDegree, int(baseMessageModulus))

	vec.RotateInPlace(lutRaw, -offset)
	for i := polyDegree - offset; i < polyDegree; i++ {
		lutRaw[i] = -lutRaw[i]
	}
	for j := 0; j < polyDegree; j++ {
		lutOut.Value[0].Coeffs[j] = lutRaw[j]
	}
}

func (e *Evaluator[T]) BootstrapFullDomainAssign(ct LWECiphertext[T], lutCompress LookUpTable[T], lutEval LookUpTable[T], ctOut LWECiphertext[T]) {
	e.BootstrapLUTAssign(e.BootstrapLUT(ct, lutCompress), lutEval, ctOut)
}

func (e *Evaluator[T]) BootstrapExtendedFullDomainAssignNew(ct LWECiphertext[T], lutCompress LookUpTable[T], decomposedLut []LookUpTable[T], ctOut LWECiphertext[T]) {
	e.KeySwitchForBootstrapAssign(ct, e.buffer.ctKeySwitchForBootstrap)
	e.BlindRotateExtendedFullDomainAssignNew(e.buffer.ctKeySwitchForBootstrap, lutCompress, decomposedLut, e.buffer.ctRotate)
	e.buffer.ctRotate.ToLWECiphertextAssign(0, ctOut)
}
func (e *Evaluator[T]) BlindRotateExtendedFullDomainAssignNew(ct LWECiphertext[T], lutCompress LookUpTable[T], decomposedLUT []LookUpTable[T], ctOut GLWECiphertext[T]) {

	e.blindRotateArbitraryExtendedAssign(ct, decomposedLUT[0], e.Parameters.polyExtendFactor/2, ctOut)
	// Evaluate NegLUT
	for i := 1; i < len(decomposedLUT)-1; i++ {
		e.blindRotateArbitraryExtendedAssign(ct, decomposedLUT[i], e.Parameters.polyExtendFactor/(1<<(i+1)), e.buffer.ctEBSAcc)
		e.AddGLWEAssign(e.buffer.ctEBSAcc, ctOut, ctOut)
	}

	// FDFB
	// First BTS
	e.blindRotateLUTCompressAssign(ct, lutCompress, e.buffer.ctEBSAcc)
	e.buffer.ctEBSAcc.ToLWECiphertextAssign(0, e.buffer.ctLWEExtracted)
	e.KeySwitchForBootstrapAssign(e.buffer.ctLWEExtracted, e.buffer.ctKeySwitchForBootstrap)

	// second BTS
	e.blindRotateBaseLUTAssign(e.buffer.ctKeySwitchForBootstrap, decomposedLUT[len(decomposedLUT)-1], e.buffer.ctEBSAcc)
	e.AddGLWEAssign(e.buffer.ctEBSAcc, ctOut, ctOut)
}

func (e *Evaluator[T]) GenExtendedCompressLUTAssign(lutOut LookUpTable[T]) {

	for x := T(0); x < e.Parameters.messageModulus/2; x++ {
		start := num.DivRound(2*int(x)*e.Parameters.lookUpTableSize, int(e.Parameters.messageModulus))
		end := num.DivRound(2*(int(x)+1)*e.Parameters.lookUpTableSize, int(e.Parameters.messageModulus))
		for xx := start; xx < end; xx++ {
			e.buffer.lutRaw[xx] = (T(1)<<63/e.Parameters.messageModulus)*x + (T(1) << 62 / e.Parameters.messageModulus)
		}
	}

	offset := num.DivRound(e.Parameters.lookUpTableSize, int(e.Parameters.messageModulus))
	vec.RotateInPlace(e.buffer.lutRaw, -offset)
	for i := e.Parameters.lookUpTableSize - offset; i < e.Parameters.lookUpTableSize; i++ {
		e.buffer.lutRaw[i] = -e.buffer.lutRaw[i]
	}

	for i := 0; i < e.Parameters.polyExtendFactor; i++ {
		for j := 0; j < e.Parameters.polyDegree; j++ {
			lutOut.Value[i].Coeffs[j] = e.buffer.lutRaw[j*e.Parameters.polyExtendFactor+i]
		}
	}
}

func (e *Evaluator[T]) GenExtendedFDFBLookUpTableCustomFullAssign(f func(int) T, messageModulus T, lutOut LookUpTable[T]) {
	for x := T(0); x < e.Parameters.messageModulus/2; x++ {
		start := num.DivRound(int(x)*e.Parameters.lookUpTableSize, int(e.Parameters.messageModulus))
		end := num.DivRound((int(x)+1)*e.Parameters.lookUpTableSize, int(e.Parameters.messageModulus))
		y := f(int(x))
		for xx := start; xx < end; xx++ {
			e.buffer.lutRaw[xx] = y
		}
	}

	for x := e.Parameters.messageModulus / 2; x < e.Parameters.messageModulus; x++ {
		start := num.DivRound(int(x)*e.Parameters.lookUpTableSize, int(e.Parameters.messageModulus))
		end := num.DivRound((int(x)+1)*e.Parameters.lookUpTableSize, int(e.Parameters.messageModulus))
		y := f(int(e.Parameters.messageModulus - x + e.Parameters.messageModulus/2 - 1))
		for xx := start; xx < end; xx++ {
			e.buffer.lutRaw[xx] = -y
		}
	}

	for i := 0; i < e.Parameters.polyExtendFactor; i++ {
		for j := 0; j < e.Parameters.polyDegree; j++ {
			lutOut.Value[i].Coeffs[j] = e.buffer.lutRaw[j*e.Parameters.polyExtendFactor+i]
		}
	}
}

func (e *Evaluator[T]) GenExtendedFDFBLookUpTableAssign(f func(int) int, lutOut LookUpTable[T]) {
	e.GenExtendedFDFBLookUpTableCustomAssign(f, e.Parameters.messageModulus, e.Parameters.scale, lutOut)
}

func (e *Evaluator[T]) GenExtendedFDFBLookUpTableCustomAssign(f func(int) int, messageModulus, scale T, lutOut LookUpTable[T]) {
	e.GenExtendedFDFBLookUpTableCustomFullAssign(func(x int) T { return e.EncodeLWECustom(f(x), messageModulus, scale).Value }, messageModulus, lutOut)
}

func (e *Evaluator[T]) FDFBLUTAssign(ct LWECiphertext[T], compressLUT LookUpTable[T], fdfbLUT LookUpTable[T], ctOut LWECiphertext[T]) {
	switch e.Parameters.bootstrapOrder {
	case OrderKeySwitchBlindRotate:
		// First BTS
		e.KeySwitchForBootstrapAssign(ct, e.buffer.ctKeySwitchForBootstrap)
		e.BlindRotateAssign(e.buffer.ctKeySwitchForBootstrap, compressLUT, e.buffer.ctRotate)
		e.buffer.ctRotate.ToLWECiphertextAssign(0, ctOut)
		// second BTS
		e.KeySwitchForBootstrapAssign(ctOut, e.buffer.ctKeySwitchForBootstrap)
		e.BlindRotateAssign(e.buffer.ctKeySwitchForBootstrap, fdfbLUT, e.buffer.ctRotate)
		e.buffer.ctRotate.ToLWECiphertextAssign(0, ctOut)
	case OrderBlindRotateKeySwitch:
		// First BTS
		e.BlindRotateAssign(ct, compressLUT, e.buffer.ctRotate)
		e.buffer.ctRotate.ToLWECiphertextAssign(0, e.buffer.ctExtract)
		e.KeySwitchForBootstrapAssign(e.buffer.ctExtract, ctOut)
		// second BTS
		e.BlindRotateAssign(ctOut, fdfbLUT, e.buffer.ctRotate)
		e.buffer.ctRotate.ToLWECiphertextAssign(0, e.buffer.ctExtract)
		e.KeySwitchForBootstrapAssign(e.buffer.ctExtract, ctOut)
	}
}

func (e *Evaluator[T]) BlindRotateExtendedFullDomainAssign(ct LWECiphertext[T], lutCompress LookUpTable[T], decomposedLUT []LookUpTable[T], ctOut GLWECiphertext[T]) {

	e.blindRotateArbitraryExtendedAssign(ct, decomposedLUT[0], e.Parameters.polyExtendFactor/2, ctOut)
	// Evaluate NegLUT
	for i := 1; i < len(decomposedLUT)-1; i++ {
		e.blindRotateArbitraryExtendedAssign(ct, decomposedLUT[i], e.Parameters.polyExtendFactor/(1<<(i+1)), e.buffer.ctEBSAcc)
		e.AddGLWEAssign(e.buffer.ctEBSAcc, ctOut, ctOut)
	}
	// FDFB
	// First BTS
	e.blindRotateLUTCompressAssign(ct, lutCompress, e.buffer.ctEBSAcc)
	e.buffer.ctEBSAcc.ToLWECiphertextAssign(0, e.buffer.ctLWEExtracted)
	e.KeySwitchForBootstrapAssign(e.buffer.ctLWEExtracted, e.buffer.ctKeySwitchForBootstrap)

	// second BTS
	e.blindRotateBaseLUTAssign(e.buffer.ctKeySwitchForBootstrap, decomposedLUT[len(decomposedLUT)-1], e.buffer.ctEBSAcc)
	e.AddGLWEAssign(e.buffer.ctEBSAcc, ctOut, ctOut)
}
