package tfhe

import (
	"math"

	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/vec"
)

func (e *Evaluator[T]) NewDecomposedLutEBS() []LookUpTable[T] {
	length := int(math.Log2(float64(e.Parameters.lookUpTableSize/2048))) + 1
	decomposedLut := make([]LookUpTable[T], length)
	//gen NegLUT
	for i := 0; i < length-1; i++ {
		decomposedLut[i] = NewLookUpTableCustom[T](1<<(length-i-2), 2048)
	}
	//gen BaseLUT
	decomposedLut[length-1] = NewLookUpTableCustom[T](1, 2048)
	return decomposedLut
}
func (e *Evaluator[T]) NewDecomposedLut() []LookUpTable[T] {
	length := int(math.Log2(float64(e.Parameters.lookUpTableSize/2048))) + 1
	decomposedLut := make([]LookUpTable[T], length)
	//gen NegLUT
	for i := 0; i < length-1; i++ {
		decomposedLut[i] = NewLookUpTableCustom[T](1, 2048<<(length-i-2))
	}
	//gen BaseLUT
	decomposedLut[length-1] = NewLookUpTableCustom[T](1, 2048)
	return decomposedLut
}

func (e *Evaluator[T]) GenLookUpTableNegDecomposedEBSAssign(f func(int) int, messageModulus, scale T, decomposedLutOut []LookUpTable[T]) {
	e.GenLookUpTableNegDecomposedEBSFullAssign(func(x int) T { return e.EncodeLWECustom(f(x), messageModulus, scale).Value }, messageModulus, decomposedLutOut)
}
func (e *Evaluator[T]) GenLookUpTableNegDecomposedEBSFullAssign(f func(int) T, messageModulus T, decomposedLutOut []LookUpTable[T]) {
	extendFactor := e.Parameters.lookUpTableSize / 2048 // Assuming 2048 is the base poly degree
	polyDegree := 2048
	logExtendFactor := int(math.Log2(float64(extendFactor)))
	// decompose func to negacyclic functions and a base function
	funcEval := make([]T, int(messageModulus))
	for x := 0; x < int(messageModulus); x++ {
		funcEval[x] = f(x) //% messageModulus
	}
	var decomposedNegFuncEval [][]T
	currentFuncEval := funcEval
	for i := 0; i < logExtendFactor; i++ {
		n := len(currentFuncEval) / 2
		newFuncEval := make([]T, n)
		negFuncEval := make([]T, n)

		for j := 0; j < n; j++ {
			newFuncEval[j] = currentFuncEval[j]/2 + currentFuncEval[j+n]/2
			negFuncEval[j] = currentFuncEval[j]/2 - currentFuncEval[j+n]/2
		}
		decomposedNegFuncEval = append(decomposedNegFuncEval, negFuncEval)
		currentFuncEval = newFuncEval
	}

	baseFuncEval := currentFuncEval
	//generate NegLUT from decomposed func
	for k := 0; k < len(decomposedNegFuncEval); k++ {
		length := e.Parameters.lookUpTableSize / (1 << (k + 1))
		lutRaw := make([]T, length)
		extendFactor := length / 2048
		for x := 0; x < int(messageModulus)/(1<<(k+1)); x++ {
			start := num.DivRound(x*e.Parameters.lookUpTableSize, int(messageModulus))
			end := num.DivRound((x+1)*e.Parameters.lookUpTableSize, int(messageModulus))
			y := decomposedNegFuncEval[k][x]
			for xx := start; xx < end; xx++ {
				lutRaw[xx] = y

			}
		}
		offset := num.DivRound(e.Parameters.lookUpTableSize, int(2*messageModulus))
		vec.RotateInPlace(lutRaw, -offset)
		for i := length - offset; i < length; i++ {
			lutRaw[i] = -lutRaw[i]
		}
		for i := 0; i < extendFactor; i++ {
			for j := 0; j < polyDegree; j++ {
				decomposedLutOut[k].Value[i].Coeffs[j] = lutRaw[j*extendFactor+i]
			}
		}
	}

	// generate BaseLUT for FDFB from base func
	baseMessageModulus := e.Parameters.messageModulus / T(extendFactor)
	length := polyDegree
	lutRaw := make([]T, length)

	for x := T(0); x < baseMessageModulus/2; x++ {
		start := num.DivRound(int(x)*polyDegree, int(baseMessageModulus))
		end := num.DivRound((int(x)+1)*polyDegree, int(baseMessageModulus))
		y := baseFuncEval[int(x)]
		for xx := start; xx < end; xx++ {
			lutRaw[xx] = y
		}
	}
	for x := baseMessageModulus / 2; x < baseMessageModulus; x++ {
		start := num.DivRound(int(x)*polyDegree, int(baseMessageModulus))
		end := num.DivRound((int(x)+1)*polyDegree, int(baseMessageModulus))
		y := baseFuncEval[int(baseMessageModulus-x+baseMessageModulus/2-1)]
		for xx := start; xx < end; xx++ {
			lutRaw[xx] = -y
		}
	}

	for j := 0; j < polyDegree; j++ {
		decomposedLutOut[logExtendFactor].Value[0].Coeffs[j] = lutRaw[j]
	}
}

func (e *Evaluator[T]) GenLookUpTableNegDecomposedAssign(f func(int) int, messageModulus, scale T, decomposedLutOut []LookUpTable[T]) {
	e.GenLookUpTableNegDecomposedFullAssign(func(x int) T { return e.EncodeLWECustom(f(x), messageModulus, scale).Value }, messageModulus, decomposedLutOut)
}
func (e *Evaluator[T]) GenLookUpTableNegDecomposedFullAssign(f func(int) T, messageModulus T, decomposedLutOut []LookUpTable[T]) {
	extendFactor := e.Parameters.lookUpTableSize / 2048 // Assuming 2048 is the base poly degree
	polyDegree := 2048
	logExtendFactor := int(math.Log2(float64(extendFactor)))
	// decompose func to negacyclic functions and a base function
	funcEval := make([]T, int(messageModulus))
	for x := 0; x < int(messageModulus); x++ {
		funcEval[x] = f(x) //% messageModulus
	}
	var decomposedNegFuncEval [][]T
	currentFuncEval := funcEval
	for i := 0; i < logExtendFactor; i++ {
		n := len(currentFuncEval) / 2
		newFuncEval := make([]T, n)
		negFuncEval := make([]T, n)

		for j := 0; j < n; j++ {
			newFuncEval[j] = currentFuncEval[j]/2 + currentFuncEval[j+n]/2
			negFuncEval[j] = currentFuncEval[j]/2 - currentFuncEval[j+n]/2
		}
		decomposedNegFuncEval = append(decomposedNegFuncEval, negFuncEval)
		currentFuncEval = newFuncEval
	}

	baseFuncEval := currentFuncEval
	//generate NegLUT from decomposed func
	for k := 0; k < len(decomposedNegFuncEval); k++ {
		length := e.Parameters.lookUpTableSize / (1 << (k + 1))
		lutRaw := make([]T, length)
		for x := 0; x < int(messageModulus)/(1<<(k+1)); x++ {
			start := num.DivRound(x*e.Parameters.lookUpTableSize, int(messageModulus))
			end := num.DivRound((x+1)*e.Parameters.lookUpTableSize, int(messageModulus))
			y := decomposedNegFuncEval[k][x]
			for xx := start; xx < end; xx++ {
				lutRaw[xx] = y

			}
		}
		offset := num.DivRound(e.Parameters.lookUpTableSize, int(2*messageModulus))
		vec.RotateInPlace(lutRaw, -offset)
		for i := length - offset; i < length; i++ {
			lutRaw[i] = -lutRaw[i]
		}
		for i := 0; i < 1; i++ {
			for j := 0; j < length; j++ {
				decomposedLutOut[k].Value[i].Coeffs[j] = lutRaw[j]
			}
		}
	}

	// generate BaseLUT for FDFB from base func
	baseMessageModulus := e.Parameters.messageModulus / T(extendFactor)
	length := polyDegree
	lutRaw := make([]T, length)

	for x := T(0); x < baseMessageModulus/2; x++ {
		start := num.DivRound(int(x)*polyDegree, int(baseMessageModulus))
		end := num.DivRound((int(x)+1)*polyDegree, int(baseMessageModulus))
		y := baseFuncEval[int(x)]
		for xx := start; xx < end; xx++ {
			lutRaw[xx] = y
		}
	}
	for x := baseMessageModulus / 2; x < baseMessageModulus; x++ {
		start := num.DivRound(int(x)*polyDegree, int(baseMessageModulus))
		end := num.DivRound((int(x)+1)*polyDegree, int(baseMessageModulus))
		y := baseFuncEval[int(baseMessageModulus-x+baseMessageModulus/2-1)]
		for xx := start; xx < end; xx++ {
			lutRaw[xx] = -y
		}
	}

	for j := 0; j < polyDegree; j++ {
		decomposedLutOut[logExtendFactor].Value[0].Coeffs[j] = lutRaw[j]
	}
}
