#include "openfhe.h"
#include "utils.h"
#include "algorithms.h"
#include <iostream>
#include <vector>

using namespace lbcrypto;
using namespace std;

namespace ckkssample {

void AddRotKeyForSum(const PrivateKey<DCRTPoly> privateKey, CryptoContext<DCRTPoly> cc, const int32_t size){
    //inner product에 필요한 rotation key 생성
    //최종적으로는 cc->EvalRotateKeyGen(privateKey, ??);를 수행해야함.
    //이 때, ??에 rotation key의 인덱스를 집어넣어야 하므로, array size에 대해 적절한 인덱스 값을 넣는 단계부터 시작

    //Step 1. index 찾기
    //예를 들어: size = 8일때 필요한 인덱스는? 
    //4회, 2회, 1회 rotation을 해야함. log2(8)=3 회동안, size값을 2씩 나눠가며 인덱스를 생성하면 된다.

    usint logsize = log2(size); //벡터의 크기 size의 log 계산.
    usint sizetmp = size; //size를 점점 깎아가며 인덱스를 저장할 것임
    std::vector<int32_t> arr(logsize);//여기에 index를 저장
    for(int32_t i = 0 ; i < logsize ; i++){
        sizetmp >>= 1; //2씩 나눠본다. i=0이라면 sizetmp=4 일 것이고, i=1이면 sizetmp=2...
        arr[i]=(sizetmp); //arr에 실제 값을 저장
    }
    //Step2. 키 생성
    cc->EvalRotateKeyGen(privateKey, arr);//cc 내부에 rotationkey를 저장.
}

Ciphertext<DCRTPoly> RotAndSum(const Ciphertext<DCRTPoly> ciphertext, const int32_t size) {
    //Inner product를 위해서는 arr에 저장된 각 값을 더하는 연산을 만들어내야함. (수업 슬라이드 참조)

    //가장 먼저, 필요한 변수들을 정의한다.
    const auto cc = ciphertext->GetCryptoContext(); //cryptoContext를 가져와야 이후 연산을 실행할 수 있음
    Ciphertext<DCRTPoly> result = ciphertext->Clone();//최종 출력값을 저장할 변수를 미리 생성해둔다.
    Ciphertext<DCRTPoly> tmp; //임시 변수 선언
	
    const int32_t logsize = log2(size); // keygen때와 마찬가지로, 회전을 몇번할것인지 생각해봄
	int32_t sizetmp=size; //keygen때와 마찬가지로, sizetmp값을 2씩 나눠가며 회전시킬것임
	for(int32_t s=0 ; s < logsize ; s++){
		sizetmp >>=1;
        tmp = cc->EvalRotate(result, sizetmp); //sizetmp에 맞게 회전
        result= cc->EvalAdd(result, tmp);//회전한 값을 결과에 더한다.
	}

    return result;
}


Ciphertext<DCRTPoly> EvalPolynomial(const Ciphertext<DCRTPoly> ciphertext, const vector<double> coeff){
    //cc 생성 후, x^i 들을 저장할 ciphertext를 미리 생성한다.
    const auto cc = ciphertext->GetCryptoContext();
    vector<Ciphertext<DCRTPoly>> powers(9);

    //x^i를 생성. 
    //가장 먼저, 모든것의 기본이 될 x^{2^r} 꼴 제곱을 생성해둔다.
    powers[1]=ciphertext->Clone(); // x^1 = x이니 입력 암호문을 그대로 저장
    powers[2]=cc->EvalMult(ciphertext, ciphertext);
    cc->ModReduceInPlace(powers[2]);
    powers[4]=cc->EvalMult(powers[2], powers[2]);
    cc->ModReduceInPlace(powers[4]);
    powers[8]=cc->EvalMult(powers[4], powers[4]);
    cc->ModReduceInPlace(powers[8]);

    //그 다음으로 x^{2^r}꼴을 잘 조합하여 나머지를 생성해본다.
    powers[3]=cc->EvalMult(powers[1], powers[2]);
    cc->ModReduceInPlace(powers[3]);
    powers[5]=cc->EvalMult(powers[4], powers[1]);
    cc->ModReduceInPlace(powers[5]);
    powers[6]=cc->EvalMult(powers[4], powers[2]);
    cc->ModReduceInPlace(powers[6]);
    //x^7만큼은 미리 만들어둔 x^3을 활용하면 좀더 편하다.
    powers[7]=cc->EvalMult(powers[4], powers[3]);
    cc->ModReduceInPlace(powers[7]);

    //제곱들을 하나하나 구해두었으니, 다음 단계로 입력 coeff를 어떻게 적용할지 고민해본다.
    //가장 먼저 coeff에 몇개의 숫자가 들어있는지, 몇차 다항식을 연산할 것인지 결정해보자.
    usint degree = 9;//기본적으로 상한은 8차. 계산의 편의를 위해 이 최대 차수에 1을 더한 값을 설정해두자.
    if(coeff.size() < 9)degree = coeff.size(); //만약 coeff에 들어있는 숫자가 9개보다 적다면, 그 갯수를 상한값으로 업데이트한다. 
    //만약 degree값이 최대 차수인 8로 저장되어있었다면 coeff.size()-1로 업데이트 해야 했을 것이다.

    //결과 ciphertext를 생성하여 1차식을 미리 계산해둔다.
    Ciphertext<DCRTPoly> result=cc->EvalMult(powers[1], coeff[1]);
    //mult는 하였지만 왜 바로 rescale을 하지 않을까?

    //2차부터 degree -1 차까지 곱하고, 더하기를 반복한다.
    //왜 degree를 차수 최대값 +1로 설정했는지가 여기서 설명된다. 물론 그냥 i < degree +1 같은 방식을 사용해도 무방하다.
    for(usint i=2;i<degree;i++){
        powers[0]=cc->EvalMult(powers[i], coeff[i]);
        cc->EvalAddInPlace(result, powers[0]);
    }

    //EvalMult(powers[i], coeff[i]); 들은 모두 rescale을 하지 않은 상황이다. 만약 8차식을 계산한다면, rescale 8번을 따로 해줘야 했을 것이다.
    //하지만 어차피 coeff를 곱하는 과정에서 level소모가 동일하고 추가적인 곱셈을 할일이 없으니 rescale을 하지 않고 모아두었다가, 여기서 한번에 rescale을 한다.
    //이렇게 rescale은 mult에 이어서 바로바로 하기보다 더 좋은 타이밍에 하는것이 연산량을 줄일 수 있다.
    cc->ModReduceInPlace(result);
    
    //여기까지 진행했다면 1~8차항에 대해서는 덧셈이 완료되었다. 하지만 마지막으로 상수항을 더할 차례다.
    cc->EvalAddInPlace(result, coeff[0]);


    //더 최적화할 여지는 없을까?
    //   //8차까지의 제곱을 모두 계산해 두는것은 낭비가 아닐까?
    //   //8차까지의 제곱을 모두 저장해 두는것은 공간적인 낭비가 아닐까?
    //임의의 차수로 확장할 수는 없을까?
    //슬롯마다 다른 polynomial을 계산하는 방법은 무엇일까?
    return result;
}




Ciphertext<DCRTPoly> EvalInnerProduct(const Ciphertext<DCRTPoly> ciphertext1, const Ciphertext<DCRTPoly> ciphertext2, const usint size){
    //내적은 두 단계로 이루어짐: 곱셈과 rotandsum    
    const auto cc = ciphertext1->GetCryptoContext(); //cc 생성
    Ciphertext<DCRTPoly> result= cc->EvalMult(ciphertext1, ciphertext2); // result 선언과 동시에 mult
    cc->ModReduceInPlace(result); // mult 후에는 rescale이 필수.
    result = RotAndSum(result, size); // mult 결과를 rotandsum

    return result;
}
	


}