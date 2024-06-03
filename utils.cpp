#include "openfhe.h"
#include "utils.h"
#include <iostream>

using namespace lbcrypto;
using namespace std;

namespace ckkssample {


// //----------------------------------------------------------------------------------
// //   Error Estimation
// //----------------------------------------------------------------------------------


vector<double> randomRealArray(const usint size, const double bound) {
	vector<double> result(size);
	for (usint i = 0; i < size; ++i) {
		result[i] = (double) rand()/(RAND_MAX) * bound; //0~1사이의 숫자를 생성한 후, bound를 곱한다.
	}
	return result;
}

vector<double> randomIntArray(const usint size, const usint bound) {
	vector<double> result(size);
	for (usint i = 0; i < size; ++i) {
		result[i] = (double) (rand()%bound); // random 생성 후, bound 로 나눈 값
	}
	return result;
}

void paramcheck(const CryptoContext<DCRTPoly> cc){
    const auto cryptoParamsCKKS =
    std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(
          cc->GetCryptoParameters());
    
    auto paramsQ = cc->GetElementParams()->GetParams();

    auto paramsQP = cryptoParamsCKKS->GetParamsQP();
    BigInteger P = BigInteger(1);
    for (uint32_t i = 0; i < paramsQP->GetParams().size(); i++) {
        if (i > paramsQ.size()) {
        P = P * BigInteger(paramsQP->GetParams()[i]->GetModulus());
        }
    }
    auto QBitLength = cc->GetModulus().GetLengthForBase(2);
    auto PBitLength = P.GetLengthForBase(2);
    std::cout << "\nQ = (bit length: " << QBitLength
                << ")" << std::endl;
    std::cout << "P = (bit length: " << PBitLength << ")"
                << std::endl;

}


void precision(const Plaintext vals, const vector<double> vals2, const usint size) {
	double max = 0;
	double tmp;
    vector<double> vals1 = vals->GetRealPackedValue();

	for (usint i = 0; i < size; ++i) {
		tmp = (vals1[i]-vals2[i]);
		if(tmp < 0)tmp= -tmp;
		if(tmp > max)max=tmp;
	}
	
    double prec = -log2(max);

    cout << "Estimated precision in bits:" << prec << ", max error: " << max << endl;
}


void PolyEvalprecision(const Plaintext vals, const vector<double> vals1, const vector<double> coeff, const usint size){ 
	double max = 0;
	double tmp;
	double result;
    vector<double> truevals = vals->GetRealPackedValue();
	

	for (usint i = 0; i < size; ++i) {
		result = coeff[0];
		for (usint j = 1; j < coeff.size(); ++j) {
			result+=pow(vals1[i], j)*coeff[j];
		}

		tmp = (truevals[i]-result);
		if(tmp < 0)tmp= -tmp;
		if(tmp > max)max=tmp;
	}
	
    double prec = -log2(max);

    cout << "Estimated precision in bits:" << prec << ", max error: " << max << endl;
}


void InnerProductprecision(const Plaintext vals, const vector<double> vals1, const vector<double> vals2, const usint size){
	double tmp;
	
	double result=0;
	vector<double> truevals = vals->GetRealPackedValue();

	for (usint i = 0; i < size; ++i) {
		result+=vals1[i]*vals2[i];
	}

	tmp = (truevals[0]-result);
	if(tmp < 0)tmp= -tmp;
		
    double prec = -log2(tmp);

    cout << "Estimated precision in bits:" << prec << endl;
}

}
