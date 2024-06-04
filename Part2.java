import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Part2
 */
public class Part2 {

    public static void main(String[] args) {
        // Receber do professor:
        // - uma mensagem c cifrada -> em hexadecimal com IV como 16 primeiros bytes
        // - uma assinatura sigc para a mensagem c -> em hexadecimal
        if (args.length != 2) {
            System.out.println("Uso: java Part2 <mensagem c> <assinatura sigc>");
            return;
        }
        String cHex = args[0];
        BigInteger sigc = new BigInteger(args[1], 16);

        // Calcular hc = SHA256(c)
        byte[] hash = sha256FromHexString(cHex);
        if (hash == null) {
            System.out.println("Erro ao calcular hash SHA-256");
            return;
        }
        BigInteger hc = new BigInteger(1, hash);

        // Verificar se hc = sigc^ep mod Np
        if (hc.compareTo(sigc.modPow(Constants.epTeacher, Constants.npTeacher)) == 0) {
            System.out.println("Assinatura válida");
        } else {
            System.out.println("Assinatura inválida");
            return;
        }

        // Se sim, decifrar a mensagem c com AES (chave s, CBC, PKCS), tendo m = AES^-1(c, s)
        

    }

    // Método auxiliar para converter uma string hexadecimal para um array de bytes
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    // Método auxiliar para calcular o hash SHA-256 de uma string hexadecimal
    public static byte[] sha256FromHexString(String s) {
        byte[] data = hexStringToByteArray(s);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(data);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

}
