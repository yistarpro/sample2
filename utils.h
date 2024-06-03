
#ifndef EIF_UTILS_H
#define EIF_UTILS_H

#include "openfhe.h"
#include <iostream>

using namespace lbcrypto;
using namespace std;

namespace ckkssample {

    // //----------------------------------------------------------------------------------
	// //   Error Estimation
	// //----------------------------------------------------------------------------------

	//무작위 실수 생성
	vector<double> randomRealArray(const usint size, const double bound = 1.0);

	//무작위 정수 생성. vector<int>가 아닌 이유는, plaintext 변환에서 입력값이 double인 편이 낫기 때문이다.
	vector<double> randomIntArray(const usint size, const usint bound);

	//parameter값을 출력해주는 함수
	void paramcheck(const CryptoContext<DCRTPoly> cc);

	// //Outputs precision level
	void precision(const Plaintext vals, const vector<double> vals2, const usint size);

	// //Outputs precision level -  PolyEval용
	void PolyEvalprecision(const Plaintext vals, const vector<double> vals1, const vector<double> coeff, const usint size);

	// //Outputs precision level -  Innerproduct용
	void InnerProductprecision(const Plaintext vals, const vector<double> vals1, const vector<double> vals2, const usint size);

}
#endif
