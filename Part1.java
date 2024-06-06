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
        // ! na = 00CC0A42C0A1F3AC0F024E44DCC1756B478F2AC4093873384DBF745B84908DB82D0861D68C89B327E62126343D409DFC46EF312BB8E9FE643CD6879FA18B17B905C37FD144332397F873A91329B891C392B34DD50A9D8FB5E2B47DC6DCEF75443BD6FFA44539C22A09BA1E5BAB518BFEDCEB3703BADEB5B91F5F6669E089B9F559DFD1AC6DEB2FD9D0E2B3B2E2D018F08E696FEC479A5D9688EAAA55FFE8596CC6EBFDBB13AB5A72C89CDB375A6A5B26160EDAE68C30A63401AC22DCE3FABB32668F6C86A3E4CD38199885F836CFFDBA54DF3BAF5B1F76A2C3C8A7334785A304BBEB0A1634F736A583B57FE0619CA3C96B16F4D70118EBEB5B6F2A04740F0E79BD
        BigInteger na = p.multiply(q);

        // Calcular L = (p-1).(q-1) -> função j de Euler
        BigInteger l = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        // Encontrar um ea que seja primo relativo de L, ou seja, MDC(ea, L) = 1
        // ! ea = 00EF5CEBF07C916F592087FC5373FC0F2A34A9DEAE44844C173324227D60FFCFB7861E1E6AC49FF2318432E5C7875782B860AEEB50EABC9A34F487449FA4E7A11628C23247ABEACECE66C216C8E1410FCAFD9E68638A8C3C9E3C990FFF383B58FE8BF766A8CBDB676230E2DF3ADF99B244F19303BB5C4BF8AAEB11C9DC5B06F1FD
        BigInteger ea = findRelativePrime(l);

        // Calcular o inverso da de ea em ZL, ou seja, da.ea = 1 em ZL
        // ! da = 67AFF4F1A4FEA20D75716EB7A99277D616E51A8695EAA49D6AFF50A8D9C951D6CE96F3015C1FBE81B29DB68EFB1B58D5F65F516B9538AF01E9B907B916497EA9FAC0A164949B885F493A92AFFE22331A156A84E1169FEA4263310DC06129F026ABF205C29C02C271563779F70EA082605BE228340F849FC2867C6D5C9CE6DA912DC5A1F882D6D5E0593EBB7EA6942533C10B4684B87167E93C415B3E7D9987FB4CCD2CB496EA5AF32A25AED2C6BFCF269320C15298A405307F6E6531F054BDB905BAF94421BE992C5CF022982E78C91E252DF1A09F1561C47912B5E80AEA0BAE31C2EF7438F256B0704DB9C84DF0BC0719E13F02EB2D16A2415D1D8AD8D97285
        BigInteger da = ea.modInverse(l);

        // Guardar a chave pública pka = (ea, Na) e a chave privada ska = (da, Na)

        // [PARTE 2] Gerar chave simétrica, Cifrar chave simétrica, Assinar texto
        // cifrado

        // Escolher um valor aleatório s de 128 bit -> chave a ser usada no AES
        // ! s = 00C271F4268C211B12FA4E700DD7DA1042
        BigInteger s = new BigInteger(128, new SecureRandom());

        // Calcular x = s^ep mod Np -> cifra a chave usando a chave pública do professor
        // ! x = 1505ABB0D8F5CDC6277C94FF922294BD18FD4E04415E4928A9E4651C9FDCADA16D9C5BFCCE63297C35EDA80F95C394B8F7193AA7FA042B9564E378FC4ABA362FE5F7824B2FB9A91AC3607EBECAE991BB09300A982797F68F78087252C42439BCE39609427EF691224DE00F508D8E703A5B69F57EDB46D45C4AF26E37085899F6892E7A2DA383CDE0A6070A308D24EEAF29923F08DF51F823A0C8F70AFF1AE8BE61FE2F3BDA9C5295EE6E7F93EB8D49581BBA930B7FE7C4287D9FF78E33E68F8548818D1B40697FADF9C088C34F46851B114B103AAC4425B4A18C092193F1FB423A95E3C8D18AEE9F0067CCA294CF8E96C97117BDF013E41EBC2F271B44C6AB84
        BigInteger x = s.modPow(Constants.epTeacher, Constants.npTeacher);

        // Calcular sigx = x^da mod Na -> assina a mensagem usando a chave privada do
        // aluno
        // ! sigx = 2D9F31DA3AF6BC2CF0BC1CA115D3423C0FB73CF3DA64A09223AE17A25ED59C736659ABFA3B1AD177A74CAA2747A04AC536A48B28D6BE714DE23C74E5025D3518161C69A8703320E4ABA1E75A6B8A27FB5DE4D17805301920B896996A9F16ED99CD8E5BBF08062CA3A3CE7370C8BE6DA73149A165076C6D20F8F02B6DB2224A9DA5E22D044780286CF45A8BC477D1BAF5FF006F7229F3B77E59F51450FD86D58AC823AB34699734B5F3C5FE2B21DE0CD1B70312926BB673EC26A891D34F698E57BF95043A445565129ED68C0C113FD9491D6E22E63443A97412345DF2DB235405E9A21A0D681EA6127AE4FBE4150312761C3997DBAC6F35E32F47EE3DF8D5900E
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
        BigInteger e = BigInteger.probablePrime(1024, new SecureRandom());
        while (l.gcd(e).compareTo(BigInteger.ONE) != 0) {
            e = BigInteger.probablePrime(1024, new SecureRandom());
        }
        return e;
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
