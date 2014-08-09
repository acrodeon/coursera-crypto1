##############################################
# Crypto Week 5: meet in the middle for DLOG #
##############################################

# gmpy2: an environment that supports multi-precision and modular arithmetic.
from gmpy2 import mpz, powmod, divm


P = "13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084171"
G = "11717829880366207009516117596335367088558084999998952205599979459063929499736583746670572176471460312928594829675428279466566527115212748467589894601965568"
H = "3239475104050450443565264378728065788649097520952449527834792452971981976143292558073856937958553180532878928001494706097394108577585732452307673444020333"


class Dlog(object):
    """to compute discrete log modulo a prime p. Let g be some element in Z∗p and suppose you are given h in Z∗p such that h=gx where 1≤x≤240"""
    
    def printDlog(self, p=P, g=G, h=H):
        """an algorithm that runs in time roughly sqr(2**40)−−−2**20 using a meet in the middle attack"""
        p = mpz(p)
        g = mpz(g)
        h = mpz(h)

        dico = {}
        # h = g**x where x = x0 * 2**20 + x1
        # For x0 in 0 .. 2**20 -1 compute h div g**x1 mod p
        for x1 in range(2**20):
            dicoKey = divm(h, powmod(g, x1, p), p)
            try:
                # if dicoKey has been already computed or Exception otherwise
                dico[dicoKey].append(x1)
            except Exception as e:
                dico[dicoKey] = [x1]

         # search x0 in 0 ... 2**20 -1 such that (g**(x0 * 2**20)) is a dicoKey
        for x0 in range(2**20):
             rightSide = powmod(g, x0 * (2**20), p)
             if rightSide in dico.keys ():
                print("x is {0} * 2**20 + {1}".format(x0, dico[rightSide][0]))
                print(x0 * 2 ** 20 + dico[rightSide][0])
                break
                 
##################
# Main() to test #
##################
if __name__ == '__main__':
    dlog = Dlog()
    dlog.printDlog()

