package tfhe

import (
	"math/bits"

	"github.com/sp301415/tfhe-go/math/csprng"
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/math/vec"
)

// Encryptor encrypts and decrypts TFHE plaintexts and ciphertexts.
// This is meant to be private, only for clients.
//
// Encryptor is not safe for concurrent use.
// Use [*Encryptor.ShallowCopy] to get a safe copy.
type Encryptor[T TorusInt] struct {
	// Encoder is an embedded encoder for this Encryptor.
	*Encoder[T]
	// GLWETransformer is an embedded GLWETransformer for this Encryptor.
	*GLWETransformer[T]

	// Parameters is the parameters for this Encryptor.
	Parameters Parameters[T]

	// UniformSampler is used for sampling the mask of encryptions.
	UniformSampler *csprng.UniformSampler[T]
	// BinarySampler is used for sampling LWE and GLWE key.
	BinarySampler *csprng.BinarySampler[T]
	// GaussainSampler is used for sampling noise in LWE and GLWE encryption.
	GaussianSampler *csprng.GaussianSampler[T]

	// PolyEvaluator is a PolyEvaluator for this Encryptor.
	PolyEvaluator *poly.Evaluator[T]

	// SecretKey is the LWE and GLWE key for this Encryptor.
	//
	// The LWE key used for LWE ciphertexts is determined by
	// BootstrapOrder.
	// For encrypting/decrypting LWE ciphertexts, use [*Encryptor DefaultLWEKey].
	SecretKey SecretKey[T]

	buffer encryptionBuffer[T]
}

// encryptionBuffer is a buffer for Encryptor.
type encryptionBuffer[T TorusInt] struct {
	// ptGLWE is the GLWE plaintext for GLWE encryption / decryptions.
	ptGLWE GLWEPlaintext[T]
	// ctGLWE is the standard GLWE Ciphertext for Fourier encryption / decryptions.
	ctGLWE GLWECiphertext[T]
	// ptGGSW is GLWEKey * Pt in GGSW encryption.
	ptGGSW poly.Poly[T]
}

// NewEncryptor returns a initialized Encryptor with given parameters.
// It also automatically samples LWE and GLWE key.
func NewEncryptor[T TorusInt](params Parameters[T]) *Encryptor[T] {
	// Fill samplers to call encryptor.GenSecretKey()
	encryptor := Encryptor[T]{
		Encoder:         NewEncoder(params),
		GLWETransformer: NewGLWETransformer[T](params.polyDegree),

		Parameters: params,

		UniformSampler:  csprng.NewUniformSampler[T](),
		BinarySampler:   csprng.NewBinarySampler[T](),
		GaussianSampler: csprng.NewGaussianSampler[T](),

		PolyEvaluator: poly.NewEvaluator[T](params.polyDegree),

		buffer: newEncryptionBuffer(params),
	}

	encryptor.SecretKey = encryptor.GenSecretKey()

	return &encryptor
}

func NewEncryptorHierarchyWithSharedLWEKey[T TorusInt](params Parameters[T]) []*Encryptor[T] {
	depth := bits.TrailingZeros(uint(params.polyDegree / 2048))
	encryptors := make([]*Encryptor[T], depth)

	polyDegree := params.polyDegree / 2
	lookupTableSize := params.lookUpTableSize / 2
	glweDimension := params.glweDimension / 2
	logPolyDegree := params.logPolyDegree - 1
	for i := 0; i < depth; i++ {
		// Parameter 복사해서 polyDegree, lookupTableSize 수정
		newParams := params
		newParams.polyDegree = polyDegree
		newParams.lookUpTableSize = lookupTableSize
		newParams.glweDimension = glweDimension
		newParams.logPolyDegree = logPolyDegree
		// Encryptor 생성
		encryptors[i] = NewEncryptor(newParams)

		// 다음 레벨: 절반씩 줄이기
		polyDegree /= 2
		lookupTableSize /= 2
		glweDimension /= 2
		logPolyDegree--
	}
	encryptors[0].SecretKey = encryptors[0].GenSecretKey()

	for i := 1; i < depth; i++ {
		length := encryptors[i].Parameters.glweDimension

		encryptors[i].SecretKey.LWELargeKey.Value = encryptors[0].SecretKey.LWELargeKey.Value[0:length]

		encryptors[i].SecretKey.LWEKey.Value = encryptors[i].SecretKey.LWELargeKey.Value[:encryptors[i].Parameters.lweDimension]

		glweRank := encryptors[i].Parameters.glweRank
		polyDegree := encryptors[i].Parameters.polyDegree
		for j := 0; j < glweRank; j++ {
			encryptors[i].SecretKey.GLWEKey.Value[j].Coeffs = encryptors[i].SecretKey.LWELargeKey.Value[j*polyDegree : (j+1)*polyDegree]
		}

		encryptors[i].ToFourierGLWESecretKeyAssign(encryptors[i].SecretKey.GLWEKey, encryptors[i].SecretKey.FourierGLWEKey)
	}

	return encryptors
}

// NewEncryptorWithKey returns a initialized Encryptor with given parameters and key.
// This does not copy secret keys.
func NewEncryptorWithKey[T TorusInt](params Parameters[T], sk SecretKey[T]) *Encryptor[T] {
	return &Encryptor[T]{
		Encoder:         NewEncoder(params),
		GLWETransformer: NewGLWETransformer[T](params.polyDegree),

		Parameters: params,

		UniformSampler:  csprng.NewUniformSampler[T](),
		BinarySampler:   csprng.NewBinarySampler[T](),
		GaussianSampler: csprng.NewGaussianSampler[T](),

		PolyEvaluator: poly.NewEvaluator[T](params.polyDegree),

		SecretKey: sk,

		buffer: newEncryptionBuffer(params),
	}
}

// newEncryptionBuffer creates a new encryptionBuffer.
func newEncryptionBuffer[T TorusInt](params Parameters[T]) encryptionBuffer[T] {
	return encryptionBuffer[T]{
		ptGLWE: NewGLWEPlaintext(params),
		ctGLWE: NewGLWECiphertext(params),
		ptGGSW: poly.NewPoly[T](params.polyDegree),
	}
}

// ShallowCopy returns a shallow copy of this Encryptor.
// Returned Encryptor is safe for concurrent use.
func (e *Encryptor[T]) ShallowCopy() *Encryptor[T] {
	return &Encryptor[T]{
		Encoder:         e.Encoder,
		GLWETransformer: e.GLWETransformer.ShallowCopy(),

		Parameters: e.Parameters,

		UniformSampler:  csprng.NewUniformSampler[T](),
		BinarySampler:   csprng.NewBinarySampler[T](),
		GaussianSampler: csprng.NewGaussianSampler[T](),

		SecretKey: e.SecretKey,

		PolyEvaluator: e.PolyEvaluator.ShallowCopy(),

		buffer: newEncryptionBuffer(e.Parameters),
	}
}

// DefaultLWESecretKey returns the LWE key according to the parameters.
// Returns LWELargeKey if BootstrapOrder is OrderKeySwitchBlindRotate,
// or LWEKey otherwise.
func (e *Encryptor[T]) DefaultLWESecretKey() LWESecretKey[T] {
	if e.Parameters.bootstrapOrder == OrderKeySwitchBlindRotate {
		return e.SecretKey.LWELargeKey
	}
	return e.SecretKey.LWEKey
}

// GenSecretKey samples a new SecretKey.
// The SecretKey of the Encryptor is not changed.
func (e *Encryptor[T]) GenSecretKey() SecretKey[T] {
	sk := NewSecretKey(e.Parameters)

	if e.Parameters.blockSize == 1 {
		e.BinarySampler.SampleVecAssign(sk.LWELargeKey.Value)
	} else {
		e.BinarySampler.SampleBlockVecAssign(e.Parameters.blockSize, sk.LWELargeKey.Value[:e.Parameters.lweDimension])
		e.BinarySampler.SampleVecAssign(sk.LWELargeKey.Value[e.Parameters.lweDimension:])
	}

	e.ToFourierGLWESecretKeyAssign(sk.GLWEKey, sk.FourierGLWEKey)

	return sk
}

// GenPublicKey samples a new PublicKey.
//
// Panics when the parameters do not support public key encryption.
func (e *Encryptor[T]) GenPublicKey() PublicKey[T] {
	if !e.Parameters.IsPublicKeyEncryptable() {
		panic("Parameters do not support public key encryption")
	}

	pk := NewPublicKey(e.Parameters)

	for i := 0; i < e.Parameters.glweRank; i++ {
		e.EncryptGLWEBody(pk.GLWEKey.Value[i])
	}

	skRev := NewGLWESecretKey(e.Parameters)
	fskRev := NewFourierGLWESecretKey(e.Parameters)
	for i := 0; i < e.Parameters.glweRank; i++ {
		vec.ReverseAssign(e.SecretKey.GLWEKey.Value[i].Coeffs, skRev.Value[i].Coeffs)
	}
	e.ToFourierGLWESecretKeyAssign(skRev, fskRev)

	for i := 0; i < e.Parameters.glweRank; i++ {
		e.GaussianSampler.SamplePolyAssign(e.Parameters.GLWEStdDevQ(), pk.LWEKey.Value[i].Value[0])
		for j := 1; j < e.Parameters.glweRank+1; j++ {
			e.UniformSampler.SamplePolyAssign(pk.LWEKey.Value[i].Value[j])
			e.PolyEvaluator.ShortFourierPolyMulSubPolyAssign(pk.LWEKey.Value[i].Value[j], fskRev.Value[j-1], pk.LWEKey.Value[i].Value[0])
		}
	}

	return pk
}
