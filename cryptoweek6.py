##############################################
# Crypto Week 6: Factor N=pq                 #
##############################################

# gmpy2: an environment that supports multi-precision and modular arithmetic.
from gmpy2 import mpz, isqrt, is_prime, mul, invert, powmod, digits
import binascii

def my_exp(a, b, N):
    ret = 1
    
    while b > 0:
        if b & 1 == 1:
            ret = ret * a % N
        a = a * a % N
        b = b >> 1
    return ret % N


def challenge1 (N):
    """Factor N=p*q where abs(p-q) < 2*N**(1/4)"""
    N = mpz(N)    
    A = isqrt(N)
    while 1:
        # A = (p+q)/2 is also ceil(sqrt(N)) indeed (A-sqrt(N)) < 1
        # x integer such that p = A - x, q = A + x; x = sqrt(A*A - N)
        if pow(A, 2) > N:
            x = isqrt(pow(A, 2) - N)
            p = A - x
            q = A + x
            if ((mul(p,q) == N) and is_prime(p) and is_prime(q)):
                return (p,q)
        A = A + 1
         
def challenge2 (N):
     """Factor N=p*q where abs(p-q) < 2**11 * N**(1/4). Indeed A - sqrt(N) < 2**20"""
     return challenge1(N)

def challenge3 (N):
    """Factor N=p*q where abs(3p-2q) < N**(1/4). Indeed (3p+2q)/2  is closed to sqrt(6N). But 3p is odd and 3p+2q / 2 is not an integer. But 2(3p) is even.\
       So 6p + 4q / 2 is an integer closed to 2 * sqrt(6N) or 2==sqrt(4) so closed to sqrt(4*6*N) ie sqrt(24N)"""
    N = mpz(N)
    twentyFour_N = mul(24,N)
    A = isqrt(twentyFour_N)
    while 1:
        if pow(A, 2) > twentyFour_N:
            x = isqrt(pow(A, 2) - twentyFour_N)
            AminusX = A - x
            AplusX = A + x
            if (mul(AminusX, AplusX) == twentyFour_N):
                p,q = 0,0
                if ((AminusX % 6 == 0) and (AplusX % 4 == 0)):
                    p = AminusX // 6
                    q = AplusX // 4
                elif ((AplusX % 6 == 0) and (AminusX % 4 == 0)):
                    p = AplusX // 6
                    q = AminusX // 4
                if (is_prime(p) and is_prime(q)):
                    return (p,q)
        A = A + 1

def challenge4 (N, p, q, e, c):
    """decrypt m from c as [PKCS#1(m)]**e mod N, N=pq. FF separator was replaces by 00 in this challenge"""
    N = mpz(N)
    e = mpz(e)
    c = mpz(c)
    Phi_N = mul(p-1,q-1)
    d = invert(e, Phi_N)
    pkcs1 = powmod(c,d,N)
    # add '0' before because '02' given by hex() is just '0x2' with '0x' to be deleted
    pkcs1_hex = '0' + hex(pkcs1)[2:]
    print(pkcs1_hex)
    i = 0
    length = len(pkcs1_hex)
    while ((i+2 < length) and pkcs1_hex[i:i+2] != '00'):
        i = i + 2
    if (i+2 < length):
        return pkcs1_hex[i+2:]
    return ""

                 
##################
# Main() to test #
##################
if __name__ == '__main__':

    #challenge 1
    N1 = "179769313486231590772930519078902473361797697894230657273430081157732675805505620686985379449212982959585501387537164015710139858647833778606925583497541085196591615128057575940752635007475935288710823649949940771895617054361149474865046711015101563940680527540071584560878577663743040086340742855278549092581"
    p1,q1 = challenge1(N1)

    print("***** CHALLENGE 1 ******")
    print("p = ", p1)
    print("q = ", q1)
    if p1 < q1:
        print ("Min(p,q) = ", p1)
    else:
        print ("Min(p,q) = ", q1)

    #challenge 2
    N2 = "648455842808071669662824265346772278726343720706976263060439070378797308618081116462714015276061417569195587321840254520655424906719892428844841839353281972988531310511738648965962582821502504990264452100885281673303711142296421027840289307657458645233683357077834689715838646088239640236866252211790085787877"
    p2, q2 = challenge2(N2)
    print("***** CHALLENGE 2 ******")
    print("p = ", p2)
    print("q = ", q2)
    if p2 < q2:
        print ("Min(p,q) = ", p2)
    else:
        print ("Min(p,q) = ", q2)

   #challenge 3
    N3 = "720062263747350425279564435525583738338084451473999841826653057981916355690188337790423408664187663938485175264994017897083524079135686877441155132015188279331812309091996246361896836573643119174094961348524639707885238799396839230364676670221627018353299443241192173812729276147530748597302192751375739387929"
    p3, q3 = challenge3(N3)
    print("***** CHALLENGE 3 ******")
    print("p = ", p3)
    print("q = ", q3)
    if p3 < q3:
        print ("Min(p,q) = ", p3)
    else:
        print ("Min(p,q) = ", q3)

   #challenge 4
    c = "22096451867410381776306561134883418017410069787892831071731839143676135600120538004282329650473509424343946219751512256465839967942889460764542040581564748988013734864120452325229320176487916666402997509188729971690526083222067771600019329260870009579993724077458967773697817571267229951148662959627934791540"
    e = 65537
    print("***** CHALLENGE 4 ******")
    plaintext = challenge4 (N1, p1, q1, e, c)
    print("Secret ", plaintext)
    message = plaintext.encode("utf8")
    message = binascii.unhexlify(message)
    print(message)
    
