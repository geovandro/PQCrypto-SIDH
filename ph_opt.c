/********************************************************************************************
* Faster isogeny-based compressed key agreement
*
*
* Abstract: Pohlig-Hellman with optimal strategy
*
* Author: Geovandro C. C. F. Pereira and Javad N. Doliskani
*********************************************************************************************/

#include "SIDH_internal.h"
#include "tests/test_extras.h"
#include <string.h>

const f2elm_t **ph2_T;
#if (W_3 == 1)
const f2elm_t **ph3_T;
#else
const f2elm_t **ph3_T1;
const f2elm_t **ph3_T2;
#endif


#if (W_2 == 1)
const int ph2_path[PLEN_2] = { // w = 1
0, 0, 1, 1, 2, 2, 2, 3, 3, 4, 4, 4, 5, 5, 5, 7, 7, 7, 7, 8, 8, 8, 9, 9, 9, 9, 11, 
12, 12, 12, 13, 12, 13, 13, 13, 13, 14, 15, 16, 17, 18, 19, 16, 16, 17, 17, 18, 
19, 20, 20, 20, 20, 20, 20, 21, 21, 22, 22, 23, 22, 22, 23, 24, 25, 26, 27, 28, 
28, 29, 28, 32, 32, 31, 29, 28, 31, 32, 29, 30, 32, 32, 33, 33, 33, 33, 33, 33, 
34, 34, 34, 34, 35, 36, 37, 38, 39, 38, 39, 40, 41, 38, 38, 39, 38, 39, 39, 48, 
41, 42, 46, 47, 46, 46, 47, 48, 49, 48, 49, 50, 49, 49, 50, 51, 48, 48, 52, 48, 
48, 49, 48, 49, 50, 53, 52, 53, 54, 54, 54, 54, 54, 54, 54, 55, 55, 55, 56, 56, 
56, 57, 57, 58, 57, 60, 61, 62, 61, 62, 64, 64, 65, 66, 66, 66, 66, 67, 70, 69, 
66, 66, 67, 70, 76, 66, 66, 67, 66, 66, 66, 66, 67, 66, 69, 70, 69, 72, 75, 74, 
73, 74, 77, 78, 79, 78, 81, 80, 81, 81, 81, 81, 84, 83, 82, 83, 81, 82, 81, 81, 
85, 86, 86, 81, 86, 81, 85, 81, 81, 81, 82, 86, 84, 85, 86, 87, 88, 88, 88, 89, 
89, 88, 88, 89, 89, 89, 89, 89, 91, 91, 92, 93, 94, 94, 94, 94, 94, 94, 95, 94, 
94, 98, 95, 94, 94, 95, 94, 99, 96, 96, 97, 99, 104, 103, 101, 102, 109, 109, 
106, 106, 112, 109, 109, 111, 111, 112, 114, 114, 115, 114, 114, 114, 119, 115, 
115, 114, 114, 115, 115, 115, 127, 123, 115, 116, 114, 114, 114, 130, 135, 117, 
115, 116, 115, 115, 119, 123, 114, 130, 123, 115, 114, 115, 115, 115, 117, 117, 
131, 119, 121, 130, 135, 133, 124, 125, 127, 127, 130, 130, 131, 131, 132, 135, 
135, 135, 135, 137, 135, 135, 135, 135, 135, 135, 137, 140, 137, 135, 135, 135, 
141, 142, 135, 135, 137, 136, 142, 135, 139, 135, 141, 137, 137, 135, 137, 137, 
142, 139, 140, 141, 142, 143, 143, 143, 143, 144, 144, 143
};
#elif (W_2 == 2)
const int ph2_path[PLEN_2] = { // w = 2
0, 0, 1, 2, 2, 3, 4, 4, 4, 5, 5, 6, 7, 7, 7, 8, 8, 9, 9, 10, 11, 12, 12, 13, 12, 
14, 15, 15, 15, 15, 16, 16, 16, 17, 18, 18, 19, 20, 21, 22, 21, 21, 25, 24, 24, 
25, 25, 26, 27, 27, 27, 28, 29, 27, 28, 30, 31, 30, 31, 31, 31, 31, 31, 32, 32, 
33, 33, 34, 35, 36, 37, 38, 38, 39, 38, 41, 38, 43, 43, 41, 46, 43, 44, 45, 46, 
47, 48, 48, 50, 50, 52, 52, 48, 53, 50, 49, 48, 51, 53, 51, 52, 53, 54, 55, 56, 
57, 58, 59, 58, 58, 58, 63, 58, 58, 58, 59, 58, 61, 62, 61, 62, 63, 63, 63, 63, 
63, 63, 64, 64, 65, 65, 66, 67, 68, 69, 70, 71, 71, 71, 73, 72, 71, 71, 77, 73, 
74, 77, 76, 80, 78, 79, 80, 81, 85, 83, 84, 85, 86, 86, 86, 89, 88, 86, 86, 86, 
94, 95, 86, 86, 91, 97, 98, 86, 90, 91, 97, 90, 91, 92, 93, 94, 103, 97, 97, 98, 
99, 103
};
#elif (W_2 == 4)
const int ph2_path[PLEN_2] = { // w = 4
0, 0, 1, 2, 3, 3, 4, 4, 5, 6, 7, 7, 8, 8, 9, 10, 10, 12, 12, 13, 12, 13, 14, 15, 
16, 16, 17, 18, 18, 18, 19, 19, 20, 21, 21, 22, 22, 23, 24, 25, 26, 27, 27, 27, 
28, 28, 28, 29, 31, 32, 32, 33, 33, 33, 33, 34, 35, 35, 36, 37, 38, 39, 40, 41, 
42, 42, 41, 42, 41, 44, 43, 44, 45, 48, 47, 48, 49, 50, 51, 51, 52, 52, 52, 52, 
51, 52, 53, 54, 55, 55, 56, 56, 57, 59
};
#endif


#if (W_3 == 1)
const int ph3_path[PLEN_3] = { // w = 1
 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 4, 5, 5, 5, 6, 7, 8, 8, 8, 8, 9, 9, 10, 9, 9, 10, 
 11, 12, 12, 13, 14, 15, 16, 16, 16, 16, 16, 16, 17, 17, 18, 19, 20, 17, 17, 18, 
 19, 20, 21, 22, 22, 21, 21, 22, 24, 27, 25, 26, 27, 27, 28, 29, 30, 31, 32, 32, 
 32, 32, 32, 32, 33, 33, 33, 33, 33, 33, 33, 33, 36, 33, 33, 33, 34, 36, 36, 37, 
 38, 38, 38, 40, 41, 39, 38, 38, 40, 41, 39, 40, 43, 45, 46, 44, 45, 48, 46, 47, 
 48, 48, 48, 48, 48, 48, 49, 54, 51, 52, 53, 54, 55, 56, 57, 58, 58, 59, 61, 61, 
 62, 63, 64, 64, 64, 64, 64, 64, 64,  65, 65, 66, 65, 66, 66, 66, 66, 65, 69, 69, 
 68, 66, 65, 65, 69, 67, 67, 67, 68, 70, 70, 71, 71, 71, 71, 71, 72, 71, 71, 71, 
 71, 72, 73, 71, 71, 81, 83, 71, 71, 72, 76, 78,  73, 76, 86, 78, 77, 78, 81, 82, 
 80, 81, 82, 83, 84, 85, 86, 86, 86, 86, 86, 86, 86, 86, 86, 88, 86, 90, 86, 86, 
 89, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 101, 105, 105, 101, 102, 
 106, 105, 105, 106, 106, 108, 107, 106, 106, 110, 108, 108, 110, 110, 112, 113  
};
#elif (W_3 == 3)
const int ph3_path[PLEN_3] = { // w = 3
0, 0, 1, 2, 3, 3, 4, 4, 5, 6, 6, 8, 8, 9, 9, 9, 10, 11, 12, 13, 13, 13, 14, 15, 
16, 17, 17, 18, 19, 19, 19, 19, 20, 21, 22, 22, 23, 24, 25, 26, 27, 28, 28, 28, 
28, 28, 29, 33, 30, 32, 32, 33, 34, 34, 35, 36, 37, 38, 39, 40, 41, 42, 41, 41, 
42, 42, 44, 42, 43, 44, 43, 44, 45, 47, 50, 48, 51, 51, 51, 52, 52
};
#elif (W_3 == 6)
const int ph3_path[PLEN_3] = { // w = 6
0, 0, 1, 2, 3, 4, 5, 6, 6, 7, 8, 8, 9, 10, 10, 11, 12, 13, 13, 14, 15, 16, 16, 
17, 18, 19, 20, 21, 21, 22, 23, 24, 25, 26, 27, 27, 28, 29, 30, 30, 31
};
#endif


int intexp(int a, int x) {
    int r = a;
    
    for (int i = 0; i < x-1; i++)
        r *= a;
    
    return r;
}


void Precomp(f2elm_t invg, f2elm_t **T, int ell, int w, int e, PCurveIsogenyStruct CurveIsogeny) 
{   
    felm_t zero = {0};    
    
    for (int i = 0; i < e; i++) {     
        for (int j = 0; j < ell; j++) {
            fpcopy751(zero, T[i][j][1]);
            fpcopy751(CurveIsogeny->Montgomery_one, T[i][j][0]);
        }
    }
    for (int d = 1; d < ell; d++)
        fp2mul751_mont(invg, T[0][d - 1], T[0][d]);
    for (int u = 1; u < e; u++) {
        for (int d = 1; d < ell; d++) {
            fp2copy751(T[u - 1][d], T[u][d]);
            if ((ell & 1) == 0) {
                for (int j = 0; j < w; j++)
                    sqr_Fp2_cycl(T[u][d], CurveIsogeny->Montgomery_one);
            } else {
                for (int j = 0; j < w; j++)
                    cube_Fp2_cycl(T[u][d], CurveIsogeny->Montgomery_one);            
            }            
        }
    }    
    for (int i = 0; i < e; i++)
        for (int j = 0; j < ell; j++)
            fp2correction751(T[i][j]);
}


void PrecompT1(f2elm_t invg, f2elm_t **T1, int ell, int w, int e, PCurveIsogenyStruct CurveIsogeny) 
{   // assuming w is at most 8 bits (w in {2, ..., 2^8-1)
    felm_t zero = {0};
    int ellw = intexp(ell,w);
    
    for (int i = 0; i < e/w+1; i++) {     
        for (int j = 0; j < ellw; j++) {
            fpcopy751(zero, T1[i][j][1]);
            fpcopy751(CurveIsogeny->Montgomery_one, T1[i][j][0]);
        }
    }
    for (int d = 1; d < ellw; d++)
        fp2mul751_mont(invg, T1[0][d - 1], T1[0][d]);
    
    for (int u = 1; u < e/w+1; u++) {
        for (int d = 1; d < ellw; d++) {
            fp2copy751(T1[u - 1][d], T1[u][d]);
            if ((ell & 1) == 0) {
                for (int j = 0; j < w; j++)
                    sqr_Fp2_cycl(T1[u][d], CurveIsogeny->Montgomery_one);
            } else {
                for (int j = 0; j < w; j++)
                    cube_Fp2_cycl(T1[u][d], CurveIsogeny->Montgomery_one);            
            }            
        }
    }
    
    for (int i = 0; i < e/w+1; i++)
        for (int j = 0; j < ellw; j++)
            fp2correction751(T1[i][j]);
}


void PrecompT2(f2elm_t invg, f2elm_t **T2, int ell, int w, int e, PCurveIsogenyStruct CurveIsogeny) 
{   // Assume w is at most 8 bits (w in {2, ..., 2^8-1)
    uint64_t emodw = e % w;    
    uint64_t ell_emodw = (uint64_t)intexp(ell,emodw);
    uint64_t ellw = intexp(ell,w);
    felm_t zero = {0};
    f2elm_t invg_emodw; 
    int bits_emodw, bits_ell_emodw;
#if (W_3 == 3)
    bits_emodw = 2;
    bits_ell_emodw = 4;
#elif (W_3 == 6)    
    bits_emodw = 3;
    bits_ell_emodw = 8;    
#endif 

    for (int i = 0; i < e/w+1; i++) {     
        for (int j = 0; j < ellw; j++) {
            fpcopy751(zero, T2[i][j][1]);
            fpcopy751(CurveIsogeny->Montgomery_one, T2[i][j][0]);
        }
    }
    
    exp_Fp2_cycl(invg, &emodw, CurveIsogeny->Montgomery_one, invg_emodw, bits_emodw);    
    for (long d = 1; d < ellw; d++) {
        fp2mul751_mont(invg, T2[0][d - 1], T2[0][d]);
        exp_Fp2_cycl(T2[0][d], &ell_emodw, CurveIsogeny->Montgomery_one, T2[1][d], bits_ell_emodw);
    }
    
    
    for (int u = 2; u < e/w+1; u++) {
        for (int d = 1; d < ellw; d++) {
            fp2copy751(T2[u - 1][d], T2[u][d]);
            if ((ell & 1) == 0) {
                for (int j = 0; j < w; j++)
                    sqr_Fp2_cycl(T2[u][d], CurveIsogeny->Montgomery_one);
            } else {
                for (int j = 0; j < w; j++)
                    cube_Fp2_cycl(T2[u][d], CurveIsogeny->Montgomery_one);            
            }            
        }
    }    
    
    for (int i = 0; i < e/w+1; i++)
        for (int j = 0; j < ellw; j++)
            fp2correction751(T2[i][j]);
}


void Traverse_w_div_e(f2elm_t r, int j, int k, int z, const int *P, 
                      const f2elm_t **T, int *D, int Dlen, int ell, int w, PCurveIsogenyStruct CurveIsogeny)
{ // Assume the window size w divides the exponent e
    f2elm_t rp = {0};
    
    if (z > 1) {
        int t = P[z];
        fp2copy751(r, rp);
        for (int i = 0; i < z-t; i++) {
            if ((ell & 1) == 0) {
                for (int j = 0; j < w; j++)
                    sqr_Fp2_cycl(rp, CurveIsogeny->Montgomery_one);
            } else {
                for (int j = 0; j < w; j++)
                    cube_Fp2_cycl(rp, CurveIsogeny->Montgomery_one);            
            }
        }
        Traverse_w_div_e(rp, j + (z - t), k, t, P, T, D, Dlen, ell, w, CurveIsogeny);  
        
        fp2copy751(r, rp);
        for (int h = k; h < k + t; h++)
            fp2mul751_mont(rp, T[j + h][D[h]], rp);
        
        Traverse_w_div_e(rp, j, k + t, z - t, P, T, D, Dlen, ell, w, CurveIsogeny);
    } else {
        fp2_conj(r, rp);
        fp2correction751(rp);
        for (int t = 0; t < ell; t++) {         
            if (memcmp(T[Dlen - 1][t], rp, 2*((CurveIsogeny->pbits+7)/8)) == 0) {
                D[k] = t;
                break;
            }
        }
    }
}


void Traverse_w_notdiv_e(f2elm_t r, int j, int k, int z, const int *P, 
                         const f2elm_t **T1, const f2elm_t **T2, int *D, 
                         int Dlen, int ell, int ellw, int ell_emodw, int w, 
                         int e, PCurveIsogenyStruct CurveIsogeny)
{ // Dedicate windowed Pohlig-Hellman when w does not divide the exponent e in solving DLOG in mu_{ell^e}
    f2elm_t rp = {0};            
    
    if (z > 1) {
        int t = P[z], goleft;
        fp2copy751(r, rp);
        
        goleft = (j > 0) ? w*(z-t) : (e % w) + w*(z-t-1);        
        for (int i = 0; i < goleft; i++) {
            if ((ell & 1) == 0)
                sqr_Fp2_cycl(rp, CurveIsogeny->Montgomery_one);
            else
                cube_Fp2_cycl(rp, CurveIsogeny->Montgomery_one);            
        }

        Traverse_w_notdiv_e(rp, j + (z - t), k, t, P, T1, T2, D, Dlen, ell, ellw, ell_emodw, w, e, CurveIsogeny);  
        
        fp2copy751(r, rp);
        for (int h = k; h < k + t; h++) {
            if (j > 0)        
                fp2mul751_mont(rp, T2[j + h][D[h]], rp);
            else
                fp2mul751_mont(rp, T1[j + h][D[h]], rp);
        }
        
        Traverse_w_notdiv_e(rp, j, k + t, z - t, P, T1, T2, D, Dlen, ell, ellw, ell_emodw, w, e, CurveIsogeny);
    } else {
        fp2_conj(r, rp);
        fp2correction751(rp);
        if (!(j == 0 && k == Dlen - 1)) {
            for (int t = 0; t < ellw; t++) {
                if (memcmp(T2[Dlen-1][t], rp, 2*((CurveIsogeny->pbits+7)/8)) == 0) {
                    D[k] = t;
                    break;             
                }                
            }
        } else {
            for (int t = 0; t < ell_emodw; t++) {     
                if (memcmp(T1[Dlen - 1][t],rp, 2*((CurveIsogeny->pbits+7)/8)) == 0) {         
                    D[k] = t;
                    break;                
                }            
            }
        }
    }
}


void solve_dlog(f2elm_t r, int *D, uint64_t* d, int ell, PCurveIsogenyStruct CurveIsogeny)
{   
    if (ell == 2) {
        if (CurveIsogeny->oAbits % W_2 == 0) {
            Traverse_w_div_e(r, 0, 0, PLEN_2 - 1, ph2_path, ph2_T, D, DLEN_2, ELL2_W, W_2, CurveIsogeny);            
            from_base(D, d, DLEN_2, ELL2_W);
        }
    } else if (ell == 3) {
#if (W_3 == 1)
        Traverse_w_div_e(r, 0, 0, PLEN_3 - 1, ph3_path, ph3_T, D, DLEN_3, ELL3_W, W_3, CurveIsogeny);
#else           
        int ell_emodw = intexp(ell,CurveIsogeny->eB % W_3);
        Traverse_w_notdiv_e(r, 0, 0, PLEN_3 - 1, ph3_path, ph3_T1, ph3_T2, D, DLEN_3, ell, ELL3_W, ell_emodw, W_3, CurveIsogeny->eB, CurveIsogeny);        
#endif        
        from_base(D, d, DLEN_3, ELL3_W);        
    }    
}



