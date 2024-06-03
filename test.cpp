#define PROFILE  // turns on the reporting of timing results

#include "openfhe.h"
#include "utils.h"
#include "testcode.h"
#include "algorithms.h"


#include "schemerns/rns-leveledshe.h"

#include <iostream>

using namespace lbcrypto;
using namespace std;
using namespace ckkssample;



int main() {
	InnerProductTest();
	PolyEvalTest(50, 1, 8, 1.0 ); //Scaling Factor, iteration, degree, bound

   	
   	//bootTest(59);
    //bootTest(50);
    //bootTest(40);


}   