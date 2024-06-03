#include "openfhe.h"
#include "testcode.h"
#include "utils.h"
#include "algorithms.h"

using namespace lbcrypto;
using namespace std;

namespace ckkssample {


    void bootTest(const uint32_t scaleModSize) {

        TimeVar t;

        uint32_t multDepth = 2320/scaleModSize -10 ;
        usint logbatchSize = 13;
        uint32_t batchSize = 1 << logbatchSize;

        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetSecretKeyDist(SPARSE_TERNARY);
        //parameters.SetSecretKeyDist(UNIFORM_TERNARY);

        parameters.SetSecurityLevel(HEStd_NotSet);


        parameters.SetMultiplicativeDepth(multDepth);
        parameters.SetScalingModSize(scaleModSize);
        parameters.SetRingDim(batchSize << 1);
        parameters.SetBatchSize(batchSize);
        
        /// Bootstrap block 1 ////      

        //parameters.SetScalingTechnique(FLEXIBLEAUTO);
        parameters.SetScalingTechnique(FLEXIBLEAUTOEXT);
        cout << "Scaling Tech: " << parameters.GetScalingTechnique() << endl;

        parameters.SetFirstModSize(scaleModSize+1);


        parameters.SetNumLargeDigits(3);
        parameters.SetKeySwitchTechnique(HYBRID);


        CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

        // Enable the features that you wish to use
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        cc->Enable(ADVANCEDSHE);
       
        //// bootblock2
        cc->Enable(FHE);
        usint levelBudgetElmt= (logbatchSize >13 ) ? 1 << (logbatchSize-13) : 1 ;  

        std::vector<uint32_t> levelBudget = {levelBudgetElmt, levelBudgetElmt};


        cout << "scaleModSize: " << scaleModSize << endl;
        paramcheck(cc);
        usint depth = FHECKKSRNS::GetBootstrapDepth(levelBudget, parameters.GetSecretKeyDist());
        cout << "bootdepth: " << depth << ", levelBudget: " << levelBudgetElmt << endl;
        cout << "budgetdepth: " << multDepth-depth << endl;


        // B. Step 2: Key Generation
        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);


        TIC(t);
        cc->EvalBootstrapSetup(levelBudget);
        cout << "Boot Setup Done" << endl;
        cc->EvalBootstrapKeyGen(keys.secretKey, batchSize);
        double timeEval0 =TOC(t);
        cout<<"Boot Keygen Done: "<< timeEval0 << "ms" << endl;


        // Step 3: Encoding and encryption of inputs
        std::cout << "!!!!!!!!!!!!!!! Boot Test !!!!!!!!!!!!!!!" << std::endl;

        // Inputs
        //std::vector<double> x1 = randomDiscreteArray(batchSize, 128);
        //x1[0]=0.1;
        std::vector<double> x1 = randomRealArray(batchSize, 1.0);
        Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1, 1, multDepth - 1);
        ptxt1->SetLength(8);
        std::cout << "\n Input x1: " << ptxt1 << std::endl;
        ptxt1 = cc->MakeCKKSPackedPlaintext(x1, 1, depth+1);


        // Encrypt the encoded vectors
        auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
        Plaintext result;

        //cc->LevelReduceInPlace(c1, nullptr, multDepth-1);
        cc->Decrypt(keys.secretKey, c1, &result);
        cout<<"level: " << c1->GetLevel() <<endl;
        TIC(t);
        //c1->SetSlots(numSlotsBoot);
        auto c2 = cc->EvalBootstrap(c1,1);
        double timeEval=TOC(t);
        cc->Decrypt(keys.secretKey, c2, &result);
        precision(result, x1, batchSize);
        result->SetLength(8);
        cout << result << " :: " << "\nEstimated level: " << c2->GetLevel() << ", Time: " << timeEval << std::endl;

    } 


    void InnerProductTest() {
        
        // Step 1: Parameter Set

        uint32_t multDepth = 5; // 곱셈 한번짜리 연산이므로 1이면 충분하다.
        uint32_t batchSize = 1 << 16;
        uint32_t scaleModSize = 40;


        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(multDepth);
        parameters.SetScalingModSize(scaleModSize);
        parameters.SetRingDim(batchSize << 1);
        parameters.SetBatchSize(batchSize);
    
        CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

        // Enable the features that you wish to use
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        // cc->Enable(ADVANCEDSHE);
       
        paramcheck(cc);

        // Step 2: Key Generation
        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);

        AddRotKeyForSum(keys.secretKey, cc, batchSize);//batchSize개의 입력에 대한 innerproduct를 실험할 예정.

        // Step 3: Encoding and encryption of inputs
        std::cout << "!!!!!!!!!!!!!!! InnerProduct Test !!!!!!!!!!!!!!!" << std::endl;

        // Inputs
        std::vector<double> x1 = randomRealArray(batchSize, 1);
        std::vector<double> x2 = randomRealArray(batchSize, 1);

        Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
        Plaintext ptxt2 = cc->MakeCKKSPackedPlaintext(x2);

        //입력값을 확인해보자
        ptxt1->SetLength(16); //전체를 출력하는 것보다 일부만 체크하기
        std::cout << "\n Input x1: " << ptxt1 << std::endl;
        ptxt1 = cc->MakeCKKSPackedPlaintext(x1);//setlength로 잘랐었기 때문에, 다시한번 plaintext 생성

        // Encrypt the encoded vectors
        auto ciphertext1 = cc->Encrypt(keys.publicKey, ptxt1);
        auto ciphertext2 = cc->Encrypt(keys.publicKey, ptxt2);

        Plaintext result;

        auto c2=EvalInnerProduct(ciphertext1, ciphertext2, batchSize);
        cc->Decrypt(keys.secretKey, c2, &result);

        //정확도 체크
        InnerProductprecision(result, x1, x2, batchSize);

        //실제 Decryption 결과 내부는 어떻게 생겼을까?
        result->SetLength(8);
        cout << "Decrypted" << result << endl; 
    } 


    
	void PolyEvalTest(const uint32_t scaleModSize, const uint32_t iteration, const usint degree, const usint bound){

        TimeVar t; // 시간 체크를 위한 변수
        vector<double> timeEval(iteration); // 시간 체크를 위한 변수. 결과 저장용

        uint32_t multDepth = 10; // 8차 polynomial은 몇의 depth를 먹을까? 
        uint32_t batchSize = 1 << 16;

        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(multDepth);
        parameters.SetScalingModSize(scaleModSize);
        parameters.SetRingDim(batchSize << 1);
        parameters.SetBatchSize(batchSize);
        
        CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

        // Enable the features that you wish to use
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        // cc->Enable(ADVANCEDSHE);

        paramcheck(cc);

        // Key Generation
        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);

        // Encoding and encryption of inputs
        std::cout << "!!!!!!!!!!!!!!! Polynomial Eval Test !!!!!!!!!!!!!!!" << std::endl;
        cout << "Degree: " << degree << endl;

        // Inputs
        std::vector<double> x1 = randomRealArray(batchSize, bound);
        Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);

        //x1의 일부 값 확인
        std::cout << "\n Input x1: ";
        for(usint i=0;i<8;i++)cout << x1[i] << ", ";
        cout << endl;

        // Encrypt the encoded vectors
        ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
        auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
        Plaintext result;

        //coeff 생성
        std::vector<double> coeff = randomIntArray(degree+1, bound); //상수항 때문에 degree +1
        //vector<double> coeff = {0,0,1}; //x^2
        //vector<double> coeff = {1,2,1}; 
        //vector<double> coeff = {0,1}; //x
        cout << "Coeff: " << coeff << endl;

        for(usint j=0; j<iteration; j++){
            TIC(t);
            auto c2 = EvalPolynomial(c1, coeff);
            timeEval[j] = TOC(t); //시간 측정은, 시작할때 TIC 끝날때 TOC
            cc->Decrypt(keys.secretKey, c2, &result);
            PolyEvalprecision(result, x1, coeff, batchSize);

            result->SetLength(8);
            cout << "Result: " << result << " :: " << endl;      

            cout << "Level: " << result->GetLevel() <<  " :: " <<endl;//곱셈 횟수 소모(level)확인            
      
        }

        statTime(timeEval, iteration);
    } 


    

    void statTime(const vector<double> times, const usint iteration){
        double avg=0.0;
        double std=0.0;

        if(iteration!=1){
            for(long j=0;j<iteration;j++)avg+=times[j];
                avg/=iteration;
            for(long j=0;j<iteration;j++)std+=(times[j]-avg)*(times[j]-avg);
                std/=iteration;
                std=sqrt(std);
            cout << "Average time = " << avg << ", Std =" << std << endl;
        }else{
            cout << "Average time = " << times[0] << endl;
        }
    }

	

}
