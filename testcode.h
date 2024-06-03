#ifndef EIF_TESTCODE_H
#define EIF_TESTCODE_H

#include "openfhe.h"
#include <iostream>

using namespace lbcrypto;
using namespace std;

namespace ckkssample {


	void bootTest(const uint32_t scaleModSize);


	void InnerProductTest();

	//입력값의 범위(bound), 시험 횟수(iteration), 차수(degree)등의 요소를 더 넣어보자
	void PolyEvalTest(const uint32_t scaleModSize, const uint32_t iteration, const usint degree, const usint bound);

	//실험 횟수에 대해 통계를 내주는 코드
    void statTime(const vector<double> times, const usint iteration);


}
#endif
