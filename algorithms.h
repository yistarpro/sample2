#ifndef EIF_ALGORITHMS_H
#define EIF_ALGORITHMS_H

#include "openfhe.h"
#include <iostream>

using namespace lbcrypto;
using namespace std;

namespace ckkssample {

//class ALGORITHMS {

//public:
	//----------------------------------------------------------------------------------
	//   ADVANCED HOMOMORPHIC OPERATIONS
	//----------------------------------------------------------------------------------

    //inner product에 필요한 rotation key 생성
    void AddRotKeyForSum(const PrivateKey<DCRTPoly> privateKey, CryptoContext<DCRTPoly> cc, const int32_t size);

	//inner product에 필요한 rotation and sum 연산
	Ciphertext<DCRTPoly> RotAndSum(const Ciphertext<DCRTPoly> ciphertext, const int32_t size);

	//8차까지에서 작동하는 polynomial 연산. 
	//coeff는 어떤 순서로 구성하는게 좋을까?
	//무조건 원소 9개를 맞춘다?
	//오름차순으로 내림차순으로?
	//몇차 다항식인지 degree를 입력받는게 좋을까?
	Ciphertext<DCRTPoly> EvalPolynomial(const Ciphertext<DCRTPoly> ciphertext, const vector<double> coeff);

	Ciphertext<DCRTPoly> EvalInnerProduct(const Ciphertext<DCRTPoly> ciphertext1, const Ciphertext<DCRTPoly> ciphertext2, const usint size);
	


}
#endif
