package rsa_key_tool

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

type rsaPublicKey struct {
	*rsa.PublicKey
	extended map[string]interface{}
}

type rsaPrivateKey struct {
	rsaPublicKey
	*rsa.PrivateKey
}

func rsaPrivateKeyFromMap(jwk map[string]interface{}) (*rsaPrivateKey, error) {
	// The JWA spec for RSA Private Keys (draft rfc section 5.3.2) states that
	// only the private key exponent 'd' is REQUIRED, the others are just for
	// signature/decryption optimizations and SHOULD be included when the JWK
	// is produced. We MAY choose to accept a JWK which only includes 'd', but
	// we're going to go ahead and not choose to accept it without the extra
	// fields. Only the 'oth' field will be optional (for multi-prime keys).
	privateExponent, err := parseRSAPrivateKeyParamFromMap(jwk, "d")
	if err != nil {
		return nil, fmt.Errorf("JWK RSA Private Key exponent: %s", err)
	}
	firstPrimeFactor, err := parseRSAPrivateKeyParamFromMap(jwk, "p")
	if err != nil {
		return nil, fmt.Errorf("JWK RSA Private Key prime factor: %s", err)
	}
	secondPrimeFactor, err := parseRSAPrivateKeyParamFromMap(jwk, "q")
	if err != nil {
		return nil, fmt.Errorf("JWK RSA Private Key prime factor: %s", err)
	}
	firstFactorCRT, err := parseRSAPrivateKeyParamFromMap(jwk, "dp")
	if err != nil {
		return nil, fmt.Errorf("JWK RSA Private Key CRT exponent: %s", err)
	}
	secondFactorCRT, err := parseRSAPrivateKeyParamFromMap(jwk, "dq")
	if err != nil {
		return nil, fmt.Errorf("JWK RSA Private Key CRT exponent: %s", err)
	}
	crtCoeff, err := parseRSAPrivateKeyParamFromMap(jwk, "qi")
	if err != nil {
		return nil, fmt.Errorf("JWK RSA Private Key CRT coefficient: %s", err)
	}

	var oth interface{}
	if _, ok := jwk["oth"]; ok {
		oth = jwk["oth"]
		delete(jwk, "oth")
	}

	// JWK key type (kty) has already been determined to be "RSA".
	// Need to extract the public key information, then extract the private
	// key values.
	publicKey, err := rsaPublicKeyFromMap(jwk)
	if err != nil {
		return nil, err
	}

	privateKey := &rsa.PrivateKey{
		PublicKey: *publicKey.PublicKey,
		D:         privateExponent,
		Primes:    []*big.Int{firstPrimeFactor, secondPrimeFactor},
		Precomputed: rsa.PrecomputedValues{
			Dp:   firstFactorCRT,
			Dq:   secondFactorCRT,
			Qinv: crtCoeff,
		},
	}

	if oth != nil {
		// Should be an array of more JSON objects.
		otherPrimesInfo, ok := oth.([]interface{})
		if !ok {
			return nil, errors.New("JWK RSA Private Key: Invalid other primes info: must be an array")
		}
		numOtherPrimeFactors := len(otherPrimesInfo)
		if numOtherPrimeFactors == 0 {
			return nil, errors.New("JWK RSA Privake Key: Invalid other primes info: must be absent or non-empty")
		}
		otherPrimeFactors := make([]*big.Int, numOtherPrimeFactors)
		productOfPrimes := new(big.Int).Mul(firstPrimeFactor, secondPrimeFactor)
		crtValues := make([]rsa.CRTValue, numOtherPrimeFactors)

		for i, val := range otherPrimesInfo {
			otherPrimeinfo, ok := val.(map[string]interface{})
			if !ok {
				return nil, errors.New("JWK RSA Private Key: Invalid other prime info: must be a JSON object")
			}

			otherPrimeFactor, err := parseRSAPrivateKeyParamFromMap(otherPrimeinfo, "r")
			if err != nil {
				return nil, fmt.Errorf("JWK RSA Private Key prime factor: %s", err)
			}
			otherFactorCRT, err := parseRSAPrivateKeyParamFromMap(otherPrimeinfo, "d")
			if err != nil {
				return nil, fmt.Errorf("JWK RSA Private Key CRT exponent: %s", err)
			}
			otherCrtCoeff, err := parseRSAPrivateKeyParamFromMap(otherPrimeinfo, "t")
			if err != nil {
				return nil, fmt.Errorf("JWK RSA Private Key CRT coefficient: %s", err)
			}

			crtValue := crtValues[i]
			crtValue.Exp = otherFactorCRT
			crtValue.Coeff = otherCrtCoeff
			crtValue.R = productOfPrimes
			otherPrimeFactors[i] = otherPrimeFactor
			productOfPrimes = new(big.Int).Mul(productOfPrimes, otherPrimeFactor)
		}

		privateKey.Primes = append(privateKey.Primes, otherPrimeFactors...)
		privateKey.Precomputed.CRTValues = crtValues
	}

	key := &rsaPrivateKey{
		rsaPublicKey: *publicKey,
		PrivateKey:   privateKey,
	}

	return key, nil
}

func rsaPublicKeyFromMap(jwk map[string]interface{}) (*rsaPublicKey, error) {
	// JWK key type (kty) has already been determined to be "RSA".
	// Need to extract 'n', 'e', and 'kid' and check for
	// consistency.

	// Get the modulus parameter N.
	nB64Url, err := stringFromMap(jwk, "n")
	if err != nil {
		return nil, fmt.Errorf("JWK RSA Public Key modulus: %s", err)
	}

	n, err := parseRSAModulusParam(nB64Url)
	if err != nil {
		return nil, fmt.Errorf("JWK RSA Public Key modulus: %s", err)
	}

	// Get the public exponent E.
	eB64Url, err := stringFromMap(jwk, "e")
	if err != nil {
		return nil, fmt.Errorf("JWK RSA Public Key exponent: %s", err)
	}

	e, err := parseRSAPublicExponentParam(eB64Url)
	if err != nil {
		return nil, fmt.Errorf("JWK RSA Public Key exponent: %s", err)
	}

	key := &rsaPublicKey{
		PublicKey: &rsa.PublicKey{N: n, E: e},
	}

	// Key ID is optional, but if it exists, it should match the key.
	_, ok := jwk["kid"]
	if ok {
		_, err := stringFromMap(jwk, "kid")
		if err != nil {
			return nil, fmt.Errorf("JWK RSA Public Key ID: %s", err)
		}
		//if kid != key.KeyID() {
		//	return nil, fmt.Errorf("JWK RSA Public Key ID does not match: %s", kid)
		//}
	}

	if _, ok := jwk["d"]; ok {
		return nil, fmt.Errorf("JWK RSA Public Key cannot contain private exponent")
	}

	key.extended = jwk

	return key, nil
}

func parseRSAPrivateKeyParamFromMap(m map[string]interface{}, key string) (*big.Int, error) {
	b64Url, err := stringFromMap(m, key)
	if err != nil {
		return nil, err
	}

	paramBytes, err := joseBase64UrlDecode(b64Url)
	if err != nil {
		return nil, fmt.Errorf("invaled base64 URL encoding: %s", err)
	}

	return new(big.Int).SetBytes(paramBytes), nil
}

func stringFromMap(m map[string]interface{}, key string) (string, error) {
	val, ok := m[key]
	if !ok {
		return "", fmt.Errorf("%q value not specified", key)
	}

	str, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("%q value must be a string", key)
	}
	delete(m, key)

	return str, nil
}

func joseBase64UrlDecode(s string) ([]byte, error) {
	s = strings.Replace(s, "\n", "", -1)
	s = strings.Replace(s, " ", "", -1)
	switch len(s) % 4 {
	case 0:
	case 2:
		s += "=="
	case 3:
		s += "="
	default:
		return nil, errors.New("illegal base64url string")
	}
	return base64.URLEncoding.DecodeString(s)
}

func parseRSAPublicExponentParam(eB64Url string) (int, error) {
	eBytes, err := joseBase64UrlDecode(eB64Url)
	if err != nil {
		return 0, fmt.Errorf("invalid base64 URL encoding: %s", err)
	}
	// Only the minimum number of bytes were used to represent E, but
	// binary.BigEndian.Uint32 expects at least 4 bytes, so we need
	// to add zero padding if necassary.
	byteLen := len(eBytes)
	buf := make([]byte, 4-byteLen, 4)
	eBytes = append(buf, eBytes...)

	return int(binary.BigEndian.Uint32(eBytes)), nil
}

func parseRSAModulusParam(nB64Url string) (*big.Int, error) {
	nBytes, err := joseBase64UrlDecode(nB64Url)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 URL encoding: %s", err)
	}

	return new(big.Int).SetBytes(nBytes), nil
}
