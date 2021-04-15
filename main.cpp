#include <iostream>
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/polycore.h"
#include <chrono>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <random>
#include <pthread.h>
#include "nfl.hpp"
#include "tools.h"
#include "seal/seal.h"
#include "external_prod.h"
#include "util.h"


using namespace std;
using namespace std::chrono;
using namespace std;
using namespace seal;
using namespace seal::util;



typedef vector<Ciphertext> GSWCiphertext;


void test_external_prod(Evaluator &evaluator1, Encryptor &encryptor1, Decryptor &decryptor1, KeyGenerator &keygen,
                              shared_ptr<SEALContext> context, SecretKey sk) {

    const auto &context_data2 = context->first_context_data();
    auto &parms = context_data2->parms();
    auto &coeff_modulus = parms.coeff_modulus();
    size_t coeff_modulus_size = coeff_modulus.size();
    auto small_ntt_tables = context_data2->small_ntt_tables();
    size_t coeff_count = parms.poly_modulus_degree();
    auto pool = MemoryManager::GetPool(mm_prof_opt::FORCE_NEW);
    const int base_bits = 31;


    Plaintext gsw_plain(to_string(1));
    Plaintext msg;
    msg.resize(coeff_count);
    for (int h = 0; h < coeff_count; h++) {
        if (h == 0) {

            msg.data()[h] = 1;
            //cout<< msg.data()[h ]<<endl;
        } else
            msg.data()[h] = 0;
    }


    GSWCiphertext choice_bit;


    ///test ct of rlwe
    Plaintext test_rlwe_pt("1");

    Ciphertext test_rlwe_ct;
    encryptor1.encrypt_symmetric(test_rlwe_pt, test_rlwe_ct);

    cout<<"-----------------------------------------------"<<endl;
    cout << "Noise budget before external product=" << decryptor1.invariant_noise_budget(test_rlwe_ct) << endl;

    vector<uint64_t *> rlwe_decom;




    int duration=0;
    int interations=0;
    for(int i=base_bits; i>1; i=ceil(i/2)) {
        interations++;
        const int lvl = context_data2->total_coeff_modulus_bit_count() / i;
        choice_bit.clear();
        poc_gsw_enc128(lvl, i, context, sk, choice_bit, msg, pool, 0);

        auto gsw_enc_time_start = std::chrono::steady_clock::now();
        rwle_decompositions(test_rlwe_ct, context, lvl, i, rlwe_decom);
        /// steps for external product. Both rlwe and gsw must be crt-decomposed
        Ciphertext res_ct;
        res_ct.resize(context, context->first_context_data()->parms_id(), 2);
        poc_nfllib_external_product(choice_bit, rlwe_decom, context, lvl, res_ct, 1);
        auto gsw_enc_time_end = std::chrono::steady_clock::now();

        for (auto p : rlwe_decom) {
            free(p);
        }
        rlwe_decom.clear();


        duration = duration_cast<std::chrono::milliseconds>(gsw_enc_time_end - gsw_enc_time_start).count();

        cout<< "---------------------------------" <<endl;
        cout<< "For Base bits=" << i<<endl;
        cout << "Noise budget after external product= "
             << decryptor1.invariant_noise_budget(res_ct) << endl;

        cout << "External prod duration= " << duration <<"ms" << endl;
    }



}

void test_external_prod_chain(Evaluator &evaluator1, Encryptor &encryptor1, Decryptor &decryptor1, KeyGenerator &keygen,
                        shared_ptr<SEALContext> context, SecretKey sk) {

    const auto &context_data2 = context->first_context_data();
    auto &parms = context_data2->parms();
    auto &coeff_modulus = parms.coeff_modulus();
    size_t coeff_modulus_size = coeff_modulus.size();
    auto small_ntt_tables = context_data2->small_ntt_tables();
    size_t coeff_count = parms.poly_modulus_degree();
    auto pool = MemoryManager::GetPool(mm_prof_opt::FORCE_NEW);



    const int base_bits = 40;
    int iterations=1000;


    Plaintext gsw_plain(to_string(1));
    Plaintext msg;
    msg.resize(coeff_count);
    for (int h = 0; h < coeff_count; h++) {
        if (h == 0) {

            msg.data()[h] = 1;
            //cout<< msg.data()[h ]<<endl;
        } else
            msg.data()[h] = 0;
    }


    const int lvl = context_data2->total_coeff_modulus_bit_count() / base_bits;

    //gen gsw ct
    GSWCiphertext choice_bit;
    poc_gsw_enc128(lvl, base_bits, context, sk, choice_bit, msg, pool, 0);


    ///gen ct of rlwe
    Plaintext test_rlwe_pt("12345678");
    Ciphertext test_rlwe_ct;
    encryptor1.encrypt_symmetric(test_rlwe_pt, test_rlwe_ct);

    ///steps to crt-compose -> baseB-decompose -> crt-decompose
    vector<uint64_t *> rlwe_decom;
    rwle_decompositions(test_rlwe_ct, context, lvl, base_bits, rlwe_decom);

    Ciphertext res_ct;
    res_ct.resize(context, context->first_context_data()->parms_id(), 2);
    poc_nfllib_external_product(choice_bit, rlwe_decom, context, lvl, res_ct,1);


    cout<<"-----------------------------------------------"<<endl;
    cout << " Testing external product chain "<<endl;
    cout<<"-----------------------------------------------"<<endl;


    GSWCiphertext chain_gsw;
    poc_gsw_enc128(lvl, base_bits, context, sk, chain_gsw, msg, pool, 0);

    int i = 1;
    while (decryptor1.invariant_noise_budget(res_ct) > 0 && i<iterations) {
        i++;

        Plaintext pp;
        decryptor1.decrypt(res_ct, pp);
        cout << "Noise budget after " <<i<<" external product "<< decryptor1.invariant_noise_budget(res_ct) << endl;

        vector<uint64_t *> rlwe_decom;
        rwle_decompositions(res_ct, context, lvl, base_bits, rlwe_decom);
        poc_nfllib_external_product(choice_bit, rlwe_decom, context, lvl, res_ct,1);
        for (auto p : rlwe_decom) {
            free(p);
        }
        rlwe_decom.clear();

    }

    cout<<"-----------------------------------------------"<<endl;
    cout << " Testing bfv product chain "<<endl;
    cout<<"-----------------------------------------------"<<endl;


    Plaintext left_rlwe_pt("1");
    Ciphertext left_rlwe_ct;
    encryptor1.encrypt_symmetric(left_rlwe_pt, left_rlwe_ct);


    Ciphertext res_ct_;


    i=0;
    while (decryptor1.invariant_noise_budget(test_rlwe_ct) > 0 && i<iterations) {


        evaluator1.multiply_inplace(test_rlwe_ct, left_rlwe_ct);
        cout << "Noise budget after " <<i<<" product "<< decryptor1.invariant_noise_budget(test_rlwe_ct) << endl;
        i++;
    }
    if(i==0)
    cout << "Noise budget after " <<i<<" product "<< decryptor1.invariant_noise_budget(test_rlwe_ct) << endl;

}

int main() {
    print_example_banner("External Product Examples");
    EncryptionParameters parms(scheme_type::BFV);
    set_bfv_parms(parms);
    auto context = SEALContext::Create(parms);
    print_line(__LINE__);
    print_parameters(context);

    KeyGenerator keygen(context);

    //generating secret key
    Plaintext secret_key_pt;
    SecretKey secret_key = keygen.secret_key();

    /// generating encryptor, decryptor and evaluator
    Encryptor encryptor(context, secret_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);

    test_external_prod(evaluator, encryptor, decryptor, keygen,  context, secret_key);
    //test_external_prod_chain(evaluator, encryptor, decryptor, keygen,  context, secret_key);

    return 0;
}
