#define ui unsigned int

#include <iostream>
#include <immintrin.h>
#include <ctime>
#include <thread>
using namespace std;

const ui CK[32] = {
0x00070E15,0x1C232A31,0x383F464D,0x545B6269,
0x70777E85,0x8C939AA1,0xA8AFB6BD,0xC4CBD2D9,
0xE0E7EEF5,0xFC030A11,0x181F262D,0x343B4249,
0x50575E65,0x6C737A81,0x888F969D,0xA4ABB2B9,
0xC0C7CED5,0xDCE3EAF1,0xF8FF060D,0x141B2229,
0x30373E45,0x4C535A61,0x686F767D,0x848B9299,
0xA0A7AEB5,0xBCC3CAD1,0xD8DFE6ED,0xF4FB0209,
0x10171E25,0x2C333A41,0x484F565D,0x646B7279 };

const unsigned char SBOX[256] = {
0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48 };

inline ui ROL(ui a, int n) {
    return (a << n) | (a >> (32 - n)); //写成a>>(64-n)也是对的，移过了就会循环移回来，相当于%32
}

inline ui T(ui a) {
    ui t = (SBOX[a >> 24] << 24) + (SBOX[(a >> 16) & 255] << 16) + (SBOX[(a >> 8) & 255] << 8) + SBOX[a & 255];
    // 与255相与，每次只取最右边8位；左移后再相加，正好组成32长的t
    return  t xor ROL(t, 13) xor ROL(t, 23);
}

ui k[36];//包含初始化之后的密钥和轮密钥
void genKey(ui* org) {
    __m128i K = _mm_set_epi32(org[3], org[2], org[1], org[0]); //加密密钥
    __m128i FK = _mm_set_epi32(0xB27022DC, 0x677D9197, 0x56AA3350, 0xA3B1BAC6); //系统参数
    K = _mm_xor_si128(K, FK);
    _mm_storeu_epi32(k, K);
    for (int i = 4; i < 36; i++) k[i] = CK[i - 4];//初始化k数组
    ui xorA, xorB, t;
    for (int i = 0; i < 32; i++) {
        xorA = k[i + 1] xor k[i + 2];
        xorB = k[i + 3] xor k[i + 4];
        t = T(xorA xor xorB);
        k[i + 4] = k[i] xor t;
    }
}

ui F(ui a) {
    ui t = (SBOX[a >> 24] << 24) + (SBOX[(a >> 16) & 255] << 16) + (SBOX[(a >> 8) & 255] << 8) + SBOX[a & 255];
    return t xor ROL(t, 2) xor ROL(t, 10) xor ROL(t, 18) xor ROL(t, 24);
}

ui m[36];
void encrypto(ui* msg) {
    for (int i = 0; i < 4; i++) m[i] = msg[i];
    for (int i = 4; i < 36; i++) m[i] = k[i];
    ui xorA, xorB, t;
    for (int i = 0; i < 32; i++) {
        xorA = m[i + 1] xor m[i + 2];
        xorB = m[i + 3] xor m[i + 4];
        t = F(xorA xor xorB);
        m[i + 4] = m[i] xor t;
    }
}

void decrypto(ui* msg) {
    for (int i = 0; i < 4; i++) m[i] = msg[i];
    for (int i = 4; i < 36; i++) m[39 - i] = k[i];
    ui xorA, xorB, t;
    for (int i = 0; i < 32; i++) {
        xorA = m[i + 1] xor m[i + 2];
        xorB = m[i + 3] xor m[i + 4];
        t = F(xorA xor xorB);
        m[i + 4] = m[i] xor t;
    }
}
void multi_genKey(int n, ui* org)
{
    for (int i = 0; i < n; i++)
    {
        genKey(org);
    }
}
void multi_encrypto(int n, ui* msg)
{
    for (int i = 0; i < n; i++)
    {
        encrypto(msg);
    }
}
void multi_decrypto(int n, ui* msg)
{
    for (int i = 0; i < n; i++)
    {
        decrypto(msg);
    }
}
void multi_thread(int num, int cpunum, ui* msg, ui* org, ui* m) {
    //int cpunum = thread::hardware_concurrency();//8
    //int cpunum = 8;
    cout << "线程数：" << cpunum << " ";
    int cnum = (num + cpunum + 1) / cpunum;
    thread* th1 = new thread[cpunum];
    thread* th2 = new thread[cpunum];
    thread* th3 = new thread[cpunum];
    thread* th4 = new thread[cpunum];
    int c = cnum;
    for (int i = 0; i < cpunum; i++) {
        th1[i] = thread(multi_genKey, cnum, org);
        th2[i] = thread(multi_encrypto, cnum, msg);
        for (int i = 0; i < 4; i++) {
            msg[i] = m[35 - i];
        }
        th3[i] = thread(multi_genKey, cnum, org);
        th4[i] = thread(multi_decrypto, cnum, msg);
    }
    for (int i = 0; i < cpunum; i++)
    {
        th1[i].join();
        th2[i].join();
        th3[i].join();
        th4[i].join();
    }
}

int main()
{
    //利用循环N次来测试多线程的加速效率
    for (int N = 200000; N <= 400000; N += 100000)
    {
        cout << endl << N << ":";
        long c1 = clock();
        ui msg[4] = { 0x12345678,0x12345678 ,0x12345678,0x12345678 }; //输入明文
        ui key[4] = { 0x12345678,0x12345678 ,0x12345678,0x12345678 };
        multi_genKey(N, key);
        multi_encrypto(N, msg);
        cout << endl << "密文：";
        printf("%08x %08x %08x %08x", m[35], m[34], m[33], m[32]);
        for (int i = 0; i < 4; i++) {
            msg[i] = m[35 - i];
        }
        multi_genKey(N,key);
        multi_decrypto(N,msg);
        long c2 = clock();
        cout << endl << "明文：" ;
        printf("%08x %08x %08x %08x", m[35], m[34], m[33], m[32]);
        cout << endl << "单线程用时：" << c2 - c1 << endl;
        long c3 = clock();
        multi_thread(N, 8, msg, key, m);
        long c4 = clock();
        cout << "用时：" << c4 - c3 << endl;
        cout << "加速比：" << (c2 - c1) / ((c4 - c3) * 1.000) << endl;
    }
    return 0;
}