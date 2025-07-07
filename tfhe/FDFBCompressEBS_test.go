package tfhe_test

import (
	"fmt"
	"math"
	"testing"

	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/tfhe"
	"github.com/stretchr/testify/assert"
)

var (
	params = tfhe.ParamsEBS5.Compile()
	enc    = tfhe.NewEncryptor(params)
	pkEnc  = tfhe.NewPublicEncryptor(params, enc.GenPublicKey())
	eval   = tfhe.NewEvaluator(params, enc.GenEvaluationKeyParallel())

	paramsListEBS = []tfhe.ParametersLiteral[uint64]{
		tfhe.ParamsEBS5,
		tfhe.ParamsEBS6,
		tfhe.ParamsEBS7,
		tfhe.ParamsEBS8,
	}
)

func TestParamsEBS(t *testing.T) {
	for _, params := range paramsListEBS {
		t.Run(fmt.Sprintf("Compile/ParamsUint%v", num.Log2(params.MessageModulus)), func(t *testing.T) {
			assert.NotPanics(t, func() { params.Compile() })
		})
	}

	for _, params := range paramsListEBS {
		t.Run(fmt.Sprintf("FailureProbability/ParamsUint%v", num.Log2(params.MessageModulus)), func(t *testing.T) {
			assert.LessOrEqual(t, math.Log2(params.Compile().EstimateFailureProbability()), -60.0)
		})
	}
}

func Benchmark_FDFBCompressEBS(b *testing.B) {
	for _, params := range paramsListEBS {
		params := params.Compile()
		enc := tfhe.NewEncryptor(params)
		eval := tfhe.NewEvaluator(params, enc.GenEvaluationKeyParallel())

		compressLUT := tfhe.NewLookUpTable(eval.Parameters)
		eval.GenExtendedCompressLUTAssign(compressLUT)

		fdfbLUT := tfhe.NewLookUpTable(eval.Parameters)
		eval.GenExtendedFDFBLookUpTableAssign(func(x int) int { return 13 - 2*x }, fdfbLUT)

		ct := enc.EncryptLWE(0)
		ctOut := ct.Copy()

		b.Run(fmt.Sprintf("prec=%v", num.Log2(params.MessageModulus())), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				eval.FDFBLUTAssign(ct, compressLUT, fdfbLUT, ctOut)
			}
		})
	}
}

func Example_fdfbCompressEBS() {
	params := tfhe.ParamsEBS5.Compile()
	enc := tfhe.NewEncryptor(params)
	eval := tfhe.NewEvaluator(params, enc.GenEvaluationKeyParallel())

	compressLUT := tfhe.NewLookUpTable(eval.Parameters)
	eval.GenExtendedCompressLUTAssign(compressLUT)

	fdfbLUT := tfhe.NewLookUpTable(eval.Parameters)
	eval.GenExtendedFDFBLookUpTableAssign(func(x int) int { return 18 - 3*x }, fdfbLUT)

	ct := enc.EncryptLWE(5)
	ctOut := ct.Copy()
	eval.FDFBLUTAssign(ct, compressLUT, fdfbLUT, ctOut)
	fmt.Println(enc.DecryptLWE(ctOut))
	// Output:
	// 3
}
