//
// Created by Haris Mughees on 4/14/21.
//

#include "external_prod.h"

void set_bfv_parms(EncryptionParameters &parms) {

    // size of polynomial degree
    size_t poly_modulus_degree = 4096;

    //number of bits in plaintext modulu, seal does not allow plaintexts to be more than 62 bits
    uint64_t plaintxt_mod_bits= 62;

    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, plaintxt_mod_bits));

    //we use special CRT components of coeff mod that are compatible with nfllib
    parms.set_coeff_modulus({4611686018326724609, 4611686018309947393, 4611686018282684417});
}



void poc_gsw_enc128(const uint64_t l, const uint64_t base_bit, shared_ptr<SEALContext> context, const SecretKey sk,
                    vector<Ciphertext> &gsw_ciphertext, Plaintext gsw_plain, seal::util::MemoryPool &pool,
                    uint64_t inv) {
    Encryptor encryptor(context, sk);
    Decryptor decryptor(context, sk);
    const auto &context_data = context->first_context_data();
    auto &parms = context_data->parms();
    auto &coeff_modulus = parms.coeff_modulus();


    size_t ct_poly_count = context_data->parms().coeff_modulus().size();/// find good way of getting it
    int total_bits;
    uint64_t r_l = l;

    Ciphertext t;
    for (int j = 0; j < 2; j++) {// c0, c1
        total_bits = (context_data->total_coeff_modulus_bit_count());
        for (int p = 0; p < r_l; p++) {
            const int shift_amount = ((total_bits) - ((p + 1) * base_bit));
            Ciphertext res;
            encryptor.encrypt_zero_symmetric(res);
            //set_ciphertext(res, context);

            poc_multiply_add_plain_without_scaling_variant(gsw_plain, *context->first_context_data(), shift_amount,
                                                           res.data(j), pool, inv);


            gsw_ciphertext.push_back(res);
        }

    }

}

void poc_multiply_add_plain_without_scaling_variant(const Plaintext &plain, const SEALContext::ContextData &context_data,
                                                    const int shift_amount, uint64_t *destination,
                                                    seal::util::MemoryPool &pool, uint64_t inv = 0) {
    auto &parms = context_data.parms();
    size_t coeff_count = parms.poly_modulus_degree();
    size_t plain_coeff_count = plain.coeff_count();
    auto &coeff_modulus = parms.coeff_modulus();
    size_t coeff_mod_count = coeff_modulus.size();
    auto plain_modulus = context_data.parms().plain_modulus();
    auto coeff_div_plain_modulus = context_data.coeff_div_plain_modulus();
    uint64_t h;


    //cout<< shift_amount << endl;

    for (size_t i = 0; i < plain_coeff_count; i++) {
        // Add to ciphertext: h * m
        for (size_t j = 0; j < coeff_mod_count; j++) {
            //init empty 128 bit integers
            auto ptr(allocate_uint(coeff_mod_count, pool));
            auto ptr2(allocate_uint(coeff_mod_count, pool));
            auto ptr3(allocate_uint(coeff_mod_count, pool));
            //set 1 in lsb (it will be used for bit shifts)

            uint64_t poly_inv;
            uint64_t plain_coeff;
            if (inv > 0) {
                seal::util::try_invert_uint_mod(inv, coeff_modulus[j], poly_inv);
                plain_coeff = seal::util::multiply_uint_uint_mod(plain.data()[i], poly_inv, coeff_modulus[j]);

            } else {
                plain_coeff = plain.data()[i];
            }


            ptr2[0] = 0;
            ptr2[1] = 0;
            ptr[0] = 1;
            ptr[1] = 0;
            //use 128 bit implementation for left shifts 1<<shiftamount
            util::left_shift_uint128(ptr.get(), shift_amount, ptr2.get());
            h = seal::util::barrett_reduce_128(ptr2.get(), coeff_modulus[j]);

            //barret reduction is used for converting 128 bit interger to mod q1, q2 where q1, q2 are max 64 bits

            h = seal::util::multiply_uint_uint_mod(h, plain_coeff, coeff_modulus[j]);
            //cout<<h<<",";
            destination[i + (j * coeff_count)] = seal::util::add_uint_uint_mod(
                    destination[i + (j * coeff_count)], h, coeff_modulus[j]);
        }
    }

}

void
rwle_decompositions(Ciphertext rlwe_ct_1, shared_ptr<SEALContext> context, const uint64_t l, const uint64_t base_bit,
                    vector<uint64_t *> &rlwe_decom) {
    const auto &context_data2 = context->first_context_data();
    auto &parms2 = context_data2->parms();
    auto &coeff_modulus = parms2.coeff_modulus();
    size_t coeff_modulus_size = coeff_modulus.size();
    auto small_ntt_tables = context_data2->small_ntt_tables();
    size_t coeff_count = parms2.poly_modulus_degree();
    auto pool = MemoryManager::GetPool(mm_prof_opt::FORCE_NEW);


    //compose ciphertext for all q_i's
    context_data2->rns_tool()->base_q()->compose_array(rlwe_ct_1.data(0), coeff_count, pool);
    context_data2->rns_tool()->base_q()->compose_array(rlwe_ct_1.data(1), coeff_count, pool);


    //128 bits decomp as given in external product
    poc_decomp_rlwe128(rlwe_ct_1, l, context, rlwe_decom, base_bit, pool);

    //auto rlwe_start = std::chrono::high_resolution_clock::now();
    int ssize = rlwe_decom.size();
    for (int i = 0; i < ssize; i++) {
        //rwle_crt_decompose and poc_decompose_array does same thing but rwle_crt_decompose is slower
        //rwle_crt_decompose(rlwe_decom[i], context, pool);
        //cout<<i<<endl;
        poc_decompose_array(rlwe_decom[i], coeff_count, coeff_modulus, coeff_modulus_size, pool);

    }

}

void poc_decomp_rlwe128(Ciphertext ct, const uint64_t l, shared_ptr<SEALContext> context,
                        vector<uint64_t *> &vec_ciphertexts, int base_bit, seal::util::MemoryPool &pool) {

    assert(vec_ciphertexts.size() == 0);
    const uint64_t base = UINT64_C(1) << base_bit;
    const uint64_t mask = base - 1;

    const auto &context_data = context->get_context_data(ct.parms_id());
    auto &parms = context_data->parms();
    auto &coeff_modulus = parms.coeff_modulus();
    size_t coeff_count = parms.poly_modulus_degree();
    size_t coeff_mod_count = coeff_modulus.size();
    size_t ct_poly_count = ct.size();

    uint64_t r_l = l;
    int total_bits;
    std::uint64_t *res;

    for (int j = 0; j < ct_poly_count; j++) {// c0, c1
        total_bits = (context_data->total_coeff_modulus_bit_count());
        uint64_t *encrypted1_ptr = ct.data(j);

        for (int p = 0; p < r_l; p++) {
            vector<uint64_t *> results;
            res = (std::uint64_t *) calloc((coeff_count * coeff_mod_count), sizeof(uint64_t));
            const int shift_amount = ((total_bits) - ((p + 1) * base_bit));
            for (size_t k = 0; k < coeff_mod_count * coeff_count; k = k + 2) {
                auto ptr(allocate_uint(2, pool));
                ptr[0] = 0;
                ptr[1] = 0;
                seal::util::right_shift_uint128(&encrypted1_ptr[k], shift_amount, ptr.get());
                uint64_t temp1 = ptr[0] & mask;
                res[k] = temp1;

            }
            //results.push_back(res);
            vec_ciphertexts.push_back(res);
        }

    }

}

void poc_decompose_array(uint64_t *value, size_t count, std::vector<Modulus> coeff_modulus, size_t coeff_mod_count,
                         MemoryPoolHandle pool) {
    if (!value) {
        throw invalid_argument("value cannot be null");
    }
    if (!pool) {
        throw invalid_argument("pool is uninitialized");
    }

    if (coeff_mod_count > 1) {
        if (!product_fits_in(count, coeff_mod_count)) {
            throw logic_error("invalid parameters");
        }

        // Decompose an array of multi-precision integers into an array of arrays,
        // one per each base element
        auto value_copy(allocate_uint(count * coeff_mod_count, pool));

        auto temp_array(allocate_uint(count * coeff_mod_count, pool));

        // Merge the coefficients first
        for (size_t i = 0; i < count; i++) {
            for (size_t j = 0; j < coeff_mod_count; j++) {
                temp_array[j + (i * coeff_mod_count)] = value[j + (i * coeff_mod_count)];
            }
        }

        set_zero_uint(count * coeff_mod_count, value);

        for (size_t i = 0; i < count; i++) {
            //set_uint_uint(value, size_, value_copy.get());

            // Temporary space for 128-bit reductions
            for (size_t j = 0; j < coeff_mod_count; j++) {
                // Reduce in blocks
                uint64_t temp[2]{0, temp_array[(i * coeff_mod_count) + coeff_mod_count - 1]};
                for (size_t k = coeff_mod_count - 1; k--;) {
                    temp[0] = temp_array[(i * coeff_mod_count) + k];
                    temp[1] = barrett_reduce_128(temp, coeff_modulus[j]);
                }

                // Save the result modulo i-th base element
                //value[i] = temp[1];
                value[(j * count) + i] = temp[1];
            }
        }
    }

}

void poc_nfllib_external_product(vector<Ciphertext> gsw_enc, vector<uint64_t *> rlwe_expansion,
                                 shared_ptr<SEALContext> context, int l, Ciphertext &res_ct, int is_reusable=1) {
    const auto &context_data = context->get_context_data(gsw_enc[0].parms_id());
    auto &parms2 = context_data->parms();
    auto &coeff_modulus = parms2.coeff_modulus();
    size_t coeff_count = parms2.poly_modulus_degree();
    size_t coeff_mod_count = coeff_modulus.size();
    size_t encrypted1_size = 2;
    //auto small_ntt_tables = context_data->small_ntt_tables();

    //assert(gsw_enc.size() == encrypted1_size * l);
    //assert(rlwe_expansion.size() == encrypted1_size * l);


    int duration = 0;

    std::uint64_t *result;
    Plaintext pt_tmp;

    std::uint64_t *c00;
    c00 = (std::uint64_t *) calloc((coeff_count), sizeof(uint64_t));
    std::uint64_t *c01;
    c01 = (std::uint64_t *) calloc((coeff_count), sizeof(uint64_t));
    std::uint64_t *c10;
    c10 = (std::uint64_t *) calloc((coeff_count), sizeof(uint64_t));
    std::uint64_t *c11;
    c11 = (std::uint64_t *) calloc((coeff_count), sizeof(uint64_t));
    //auto expand_start = std::chrono::high_resolution_clock::now();

    //start = std::chrono::steady_clock::now();

    for (int k = 0; k < encrypted1_size * l; k++) {

        for (size_t j = 0; j < encrypted1_size; j++) {
            //j==0,j=1
            uint64_t *encrypted_gsw_ptr = gsw_enc[k].data(j);
            uint64_t *encrypted_rlwe_ptr = rlwe_expansion[k];
            result = (std::uint64_t *) calloc((coeff_count * coeff_mod_count), sizeof(uint64_t));


            poly_nfllib_mul(encrypted_gsw_ptr, encrypted_rlwe_ptr, result, coeff_count, coeff_mod_count, is_reusable);
            //poly_nfllib_mul_preprocessed(encrypted_gsw_ptr, encrypted_rlwe_ptr, result, coeff_count, coeff_mod_count);

            for (size_t i = 0; i < coeff_mod_count; i++) {

//                seal::util::add_poly_poly_coeffmod(res_ct.data(j) + (i*coeff_count), result+ (i*coeff_count), coeff_count, coeff_modulus[i].value(), res_ct.data(j) + (i*coeff_count));

                if (j == 0 && i == 0) {
                    seal::util::add_poly_poly_coeffmod(c00, result, coeff_count, coeff_modulus[i].value(), c00);

                } else if (j == 0 && i == 1) {
                    seal::util::add_poly_poly_coeffmod(c01, result + coeff_count, coeff_count, coeff_modulus[i].value(),
                                                       c01);
                    //myadd_poly_poly_coeffmod(c01, result, coeff_count, coeff_modulus[i].value(), c01);
                } else if (j == 1 && i == 0) {
                    seal::util::add_poly_poly_coeffmod(c10, result, coeff_count, coeff_modulus[i].value(), c10);
                    // myadd_poly_poly_coeffmod(c10, result, coeff_count, coeff_modulus[i].value(), c10);
                } else if (j == 1 && i == 1) {
                    seal::util::add_poly_poly_coeffmod(c11, result + coeff_count, coeff_count, coeff_modulus[i].value(),
                                                       c11);
                    //myadd_poly_poly_coeffmod(c11, result, coeff_count, coeff_modulus[i].value(), c11);
                }


            }

            free(result);


        }


    }


//    end = std::chrono::steady_clock::now();
//    duration= duration_cast<std::chrono::milliseconds >(end - start).count();
//    cout<<"myduration="<<duration<<endl;


    seal::util::set_poly_poly(c00, coeff_count, 1, res_ct.data(0));
    seal::util::set_poly_poly(c01, coeff_count, 1, res_ct.data(0) + coeff_count);
    seal::util::set_poly_poly(c10, coeff_count, 1, res_ct.data(1));
    seal::util::set_poly_poly(c11, coeff_count, 1, res_ct.data(1) + coeff_count);


    free(c00);
    free(c01);
    free(c10);
    free(c11);

}

void poly_nfllib_mul(std::uint64_t *p1, std::uint64_t *p2, std::uint64_t *res, const size_t coeff_count,
                     const std::uint64_t coeff_mod_count, int is_reusable=1) {

    //ternary is_reusable = 1 gsw is not reused in future, is_reusable=2 it will be reused in future so save p1 in ntt, is_reusable=3 it is reused in current mul so p1 is already in ntt

    //using poly_t = nfl::poly_from_modulus<uint32_t , 4096, 64>;
    using poly_t = nfl::poly_from_modulus<uint64_t, 4096, 128>;
    //using poly_t = nfl::poly_from_modulus<uint64_t, 2048, 128>;
    //using poly_t = nfl::poly_from_modulus<uint32_t , 8192, 64>;
    //4096, 124, uint64_t
    auto start = std::chrono::steady_clock::now();
    auto end = std::chrono::steady_clock::now();



//    if(is_reusable>1)
//    cout<<"is_reusable="<< is_reusable<<endl;
    //start = std::chrono::steady_clock::now();
    poly_t *resa = alloc_aligned<poly_t, 32>(1),
            *resb = alloc_aligned<poly_t, 32>(1),
            *resc = alloc_aligned<poly_t, 32>(1);

    //end = std::chrono::steady_clock::now();



    for (size_t cm = 0; cm < poly_t::nmoduli; cm++) {
        for (size_t i = 0; i < poly_t::degree; i++) {
            resa[0](cm, i) = p1[(cm * poly_t::degree) + i];
            resb[0](cm, i) = p2[(cm * poly_t::degree) + i];
        }
    }


//    std::fill(resa, resa + 1, 123234);
//    std::fill(resb, resb + 1, 123244);


    if(is_reusable!=3) {
        resa[0].ntt_pow_phi();
    }
    resb[0].ntt_pow_phi();
    nfl::mul(resc[0], resa[0], resb[0]);
    resc[0].invntt_pow_invphi();


    for (size_t cm = 0; cm < poly_t::nmoduli; cm++) {
        for (size_t i = 0; i < poly_t::degree; i++) {
            if(is_reusable==2){
                p1[cm * poly_t::degree + i] = resa[0](cm, i);
            }
            res[cm * poly_t::degree + i] = resc[0](cm, i);
        }
    }


    free_aligned(1, resa);
    free_aligned(1, resb);
    free_aligned(1, resc);


    //std::cout << "Time per polynomial NTT: " << get_time_us(start, end, 1) << " us" << std::endl;

}

