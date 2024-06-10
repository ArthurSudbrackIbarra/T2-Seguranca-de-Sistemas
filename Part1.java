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
        // ! na = 00959FEBE9936E0A531F8D69699BDF30E895438E01A661A7202E4DC02A4F1CEDF1E6944AAB16028166E8A600121CFA8862D97A72FB5D8C0ADF9973B36EB589222646FB26F3C5BA08B0DC1728F2BC752A6F79D751908642471CA3A597924AFD32B78C0B1A5757E79BE67E1693409D4182028A46CEBBC5460F23D09AE6F2FDDB81C959429E22AAC35918B9B3CC193C254BE6E02E36B79E765A0CF161DC75341D23A4DDC3BD11718E6EDD70B3855C2D6FAC0594E0131006F89596C873A69F1F7F5A61654A0D1C346D7A1F4836F536A279931E78D4EFE7C9F1D6ADC971797E6F59A0DB18061E096AAF5F0E43E64262B9831882B08D590A79E305A14D04F2BC18062B7F
        BigInteger na = p.multiply(q);

        // Calcular L = (p-1).(q-1) -> função j de Euler
        BigInteger l = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        // Encontrar um ea que seja primo relativo de L, ou seja, MDC(ea, L) = 1
        // ! ea = 594F56F6D2DC03C2CFE7ECBC0A0DD9373B89536FC0041869E9B22347EC116B7AB69F8A36E68D60C02E387DA3B10F6718C368DD420B1AF1FD3F6934D05571782B750B3E283D0EE3CDB6FDA48C27B7E7499D4EA5158C6F49FBD9D64D3A7650127788B2D7DDB35BD953B099D282B2A813B2480C1C82219AA392D4390276CFDC67D835B726AFDFD4CF0C4B047E7C06860457B054C8AE54E9B98C41191C0F3622236F750ADCA33EEABFEF3887294134915CDA24DFF6D4335C3922F0576D4E2CA7F8B41D078681D24911F1B15AB7F5FC4544DF2BA2A30F01B54C1733949FC2F0BC562AD24BDCACD73D16B3B0E04DF60535564AE4A59B512CC042815BFF67E5262B6E89
        BigInteger ea = findRelativePrime(l);
        System.out.println(l.bitLength() + " bits");

        // Calcular o inverso da de ea em ZL, ou seja, da.ea = 1 em ZL
        // ! da = 00D5D5338E70342759DC7780F0CC0284558B64CC1756AA33C9E1B5035DF514237BC37CFAF76915773FE1AD945CBC2CBD69D52C1FE54D5611E11923FAC9C016EF2746A0BBDCAFEAA114B40F6EF3608CD048D61B52BE13E37E7F5C99519020D95D9A2B54C1255E72DF08012BC54519E39169E5067B46AA6F4C16A3ED297D72DB5C8D6B3CFD39527367F6593F7C1535CCF7A65DFF591B3634A078E0630501753CF4DB8D91BAFE27D95A399E134827B826A1566E2AE1744E5B334FE0002756434FB7C38B00F58CF6B0E2BB79E58A720DBCE5451D765A983DFF0BA9B144970AE862683AE81A88CC3091A8897BA0DAAC530563412F553F9C47D7D5BE51EB8721B4B8CA1
        BigInteger da = ea.modInverse(l);

        // Guardar a chave pública pka = (ea, Na) e a chave privada ska = (da, Na)

        // [PARTE 2] Gerar chave simétrica, Cifrar chave simétrica, Assinar texto
        // cifrado

        // Escolher um valor aleatório s de 128 bit -> chave a ser usada no AES
        // ! s = 1C6F5ACA62B8C4A736AC8CF66B797C5C
        BigInteger s = new BigInteger(128, new SecureRandom());

        // Calcular x = s^ep mod Np -> cifra a chave usando a chave pública do professor
        // ! x = 13E6CB02567B52FDF6E5A666E206B04D761A9E6D955E3CBA234D6FB0FD9AD7C034EF52C6176637BDC22100F0FDA76BE4CD4329ABC9A010F0DE5A964D1FAE899A91880132D62874878F7FC0DE920826B132AA2F7340D189BA2B4CECCE1B345EDDEC5777DFC3F44B560AA571FD5E4CFE0E73EEBCFA7DCFD0DA4B22C6C5A71BE4106F4523DE85B76D7169D888EA48FD1CEBFF535A077AE96D75B5626838E55B8E2A9ADE2A9ACF0E71B2A6BDE61A13C9D33EE56C76DC55716452E5E68FDB82C9360E0AE4CE14CB45606EBAC6F5F3D1F004105BF7B2BD242F90553C6234F6C27F9134493C3D70C850ED00C29810DB79C41EA5C8C76BFCF1AAC75D24010C45A899AC06
        BigInteger x = s.modPow(Constants.epTeacher, Constants.npTeacher);

        // Calcular sigx = x^da mod Na -> assina a mensagem usando a chave privada do
        // aluno
        // ! sigx = 38ACF26928A238D65960E894D58C1B26D9ACA1BAAA07898421F7020CA95AB2612F33C76B1EAEEA6E93F6D29004E4AB5D224A9B3E29EC7DA24601A4DA20011F8B91026009F70FD39DF17707C69B4268B66514711CAE7E843310E1C27EA50DC5BE49E070F0112C883AB7AEA9A3BE4FE107C7CD789C8F8C7CB933E5D755DF3B7DA8C4E148BC6BFA5976193AE5684ED0BC65FF5523C050A48C907BB6976F0709CC3006F8F9064217117AB96418208C73697E654AB00A3DAA853BF17464802D7C4ACF82182C400E1557C4BB0C2E6974EAC4DF88C9DF93DF389ADC20A478E717BC7BF59B33FD5BF1AD0F6C7CB9A136573009E1DCDFC1D7D80F065FD51EE6E94113DD9F
        BigInteger sigx = x.modPow(da, na);

        // Enviar (x, sigx, pka) para o professor por email ou whatsapp -> todos os
        // valores em hexadecimal
        System.out.println("=== Dados a serem enviados para o professor (em hexadecimal) ===\n");
        System.out.println("x: " + bigIntegerToHex(x) + "\n");
        System.out.println("sigx: " + bigIntegerToHex(sigx) + "\n");
        System.out.println("ea: " + bigIntegerToHex(ea) + "\n");
        System.out.println("na: " + bigIntegerToHex(na));

        // Printar os valores que ficam com o aluno
        System.out.println("\n=== Valores que ficam com o aluno (em hexadecimal) ===\n");
        System.out.println("s: " + bigIntegerToHex(s) + "\n");
        System.out.println("da: " + bigIntegerToHex(da));
    }

    // Método auxiliar para encontrar um número primo relativo a L
    public static BigInteger findRelativePrime(BigInteger l) {
        BigInteger ea;
        do {
            ea = new BigInteger(l.bitLength(), new SecureRandom());
        } while (!ea.gcd(l).equals(BigInteger.ONE) || ea.compareTo(BigInteger.ONE) <= 0 || ea.compareTo(l) >= 0);
        return ea;
    }

    // Método auxiliar para receber um BigInteger e retornar o valor em hexadecimal.
    public static String bigIntegerToHex(BigInteger value) {
        String hex = value.toString(16).toUpperCase();
        // Adicionar um byte 0 no início se o valor começar com {8, 9, A, B, C, D, E, F}
        if (hex.matches("^[89A-F].*")) {
            hex = "00" + hex;
        }
        return hex;
    }
}
