import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * GenerateValues
 */
public class GenerateValues {

    // Constantes
    public static final BigInteger epTeacher = new BigInteger("2E76A0094D4CEE0AC516CA162973C895", 16);
    public static final BigInteger npTeacher = new BigInteger(
            "1985008F25A025097712D26B5A322982B6EBAFA5826B6EDA3B91F78B7BD63981382581218D33A9983E4E14D4B26113AA2A83BBCCFDE24310AEE3362B6100D06CC1EA429018A0FF3614C077F59DE55AADF449AF01E42ED6545127DC1A97954B89729249C6060BA4BD3A59490839072929C0304B2D7CBBA368AEBC4878A6F0DA3FE58CECDA638A506C723BDCBAB8C355F83C0839BF1457A3B6B89307D672BBF530C93F022E693116FE4A5703A665C6010B5192F6D1FAB64B5795876B2164C86ABD7650AEDAF5B6AFCAC0438437BB3BDF5399D80F8D9963B5414EAFBFA1AA2DD0D24988ACECA8D50047E5A78082295A987369A67D3E54FFB7996CBE2C5EAD794391",
            16);

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

        // Calcular x = sep mod Np -> cifra a chave usando a chave pública do professor
        BigInteger x = s.modPow(epTeacher, npTeacher);

        // Calcular sigx = xda mod Na -> assina a mensagem usando a chave privada do
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

    // Função auxiliar para receber um BigInteger e printar o valor em hexadecimal,
    // adicionando um bit 0 na frente caso o bit mais significativo seja 1
    public static String bigIntegerToHex(BigInteger value) {
        String hex = value.toString(16);
        char fc = hex.charAt(0);
        if (fc == '8' || fc == '9' || fc == 'a' || fc == 'b' || fc == 'c'
                || fc == 'd' || fc == 'e' || fc == 'f') {
            hex = "0" + hex;
        }
        return hex.toUpperCase();
    }
}
