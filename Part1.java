import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Part1
 */
public class Part1 {

    // Main
    public static void main(String[] args) {
        // [PARTE 1] Gerar chaves assimétricas

        // Gerar dois números primos p e q com no mínimo 1024 bits
        BigInteger p = BigInteger.probablePrime(1024, new SecureRandom());
        BigInteger q = BigInteger.probablePrime(1024, new SecureRandom());

        // Calcular Na = p.q
        BigInteger na = p.multiply(q);

        // Calcular L = (p-1).(q-1) -> função j de Euler
        BigInteger l = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        // Encontrar um ea que seja primo relativo de L, ou seja, MDC(ea, L) = 1
        BigInteger ea = findRelativePrime(l);

        // Calcular o inverso da de ea em ZL, ou seja, da.ea = 1 em ZL
        BigInteger da = ea.modInverse(l);

        // Guardar a chave pública pka = (ea, Na) e a chave privada ska = (da, Na)

        // [PARTE 2] Gerar chave simétrica, Cifrar chave simétrica, Assinar texto
        // cifrado

        // Escolher um valor aleatório s de 128 bit -> chave a ser usada no AES
        BigInteger s = new BigInteger(128, new SecureRandom());

        // Calcular x = s^ep mod Np -> cifra a chave usando a chave pública do professor
        BigInteger x = s.modPow(Constants.epTeacher, Constants.npTeacher);

        // Calcular sigx = x^da mod Na -> assina a mensagem usando a chave privada do
        // aluno
        BigInteger sigx = x.modPow(da, na);

        // Enviar (x, sigx, pka) para o professor por email ou whatsapp -> todos os
        // valores em hexadecimal
        System.out.println("x: " + bigIntegerToHex(x) + "\n");
        System.out.println("sigx: " + bigIntegerToHex(sigx) + "\n");
        System.out.println("ea: " + bigIntegerToHex(ea) + "\n");
        System.out.println("na: " + bigIntegerToHex(na));
    }

    // Função auxiliar para encontrar um número primo relativo a L
    public static BigInteger findRelativePrime(BigInteger l) {
        BigInteger e = BigInteger.probablePrime(1024, new SecureRandom());
        while (l.gcd(e).compareTo(BigInteger.ONE) != 0) {
            e = BigInteger.probablePrime(1024, new SecureRandom());
        }
        return e;
    }

    // Função auxiliar para receber um BigInteger e printar o valor em hexadecimal.
    public static String bigIntegerToHex(BigInteger value) {
        String hex = value.toString(16);
        return hex.toUpperCase();
    }
}
