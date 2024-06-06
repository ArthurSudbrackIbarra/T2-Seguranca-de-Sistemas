import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Part2
 */
public class Part2 {

    public static void main(String[] args) {
        // Receber do professor:
        // - uma mensagem c cifrada -> em hexadecimal com IV como 16 primeiros bytes
        // - uma assinatura sigc para a mensagem c -> em hexadecimal
        // Receber do próprio aluno:
        // - a chave AES s -> em hexadecimal
        // - o módulo da chave pública na -> em hexadecimal
        // - a chave privada da -> em hexadecimal
        if (args.length != 4) {
            System.out.println(
                    "\nUso: java Part2 c sigc s na da\n\n"
                            +
                            "Os argumentos devem ser fornecidos em hexadecimal.\n\n" +
                            "c       : A mensagem cifrada recebida do professor.\n" +
                            "sigc    : A assinatura da mensagem cifrada fornecida pelo professor.\n" +
                            "s       : A chave simétrica AES do aluno utilizada para decifrar a mensagem.\n" +
                            "na      : O módulo Na da chave pública do aluno.\n" +
                            "da      : A chave privada da do aluno utilizada para assinar a mensagem.\n");
            return;
        }
        BigInteger c = new BigInteger(args[0], 16);
        BigInteger sigc = new BigInteger(args[1], 16);
        BigInteger s = new BigInteger(args[2], 16);
        BigInteger na = new BigInteger(args[3], 16);
        BigInteger da = new BigInteger(args[4], 16);

        // Calcular hc = SHA256(c)
        byte[] hash = sha256Hash(c);
        if (hash == null) {
            System.out.println("Erro ao calcular hash SHA-256");
            return;
        }
        BigInteger hc = new BigInteger(1, hash);

        // Verificar se hc = sigc^ep mod Np
        if (hc.compareTo(sigc.modPow(Constants.epTeacher, Constants.npTeacher)) != 0) {
            System.out.println("Assinatura inválida");
        }
        System.out.println("Assinatura válida");

        // Se sim, decifrar a mensagem c com AES (chave s, CBC, PKCS), tendo m =
        // AES^-1(c, s)
        String m;
        try {
            m = decryptAES(c, s);
            System.out.println("Mensagem decifrada: " + m);
        } catch (Exception e) {
            System.out.println("Erro ao decifrar a mensagem: " + e.getMessage());
            return;
        }

        // Inverter a mensagem m decifrada gerando minv. Exemplo, se m = “pucrs”, então minv “srcup”
        String minv = reverseString(m);

        // Gerar um IV aleatório
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);

        // Cifrar minv usando AES (chave s, CBC, PKCS), tendo cinv = concatenar(IV, AES(minv, s))
        byte[] cipherText;
        try {
            cipherText = encryptAES(minv, s, iv);
        } catch (Exception e) {
            System.out.println("Erro ao cifrar a mensagem: " + e.getMessage());
            return;
        }
        byte[] cinvBytes = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, cinvBytes, 0, iv.length);
        System.arraycopy(cipherText, 0, cinvBytes, iv.length, cipherText.length);
        BigInteger cinv = new BigInteger(1, cinvBytes);

        // Calcular hinv = SHA256(cinv)
        byte[] hinv = sha256Hash(cinv);

        // Calcular sighinv = hinv^da mod Na
        BigInteger sighinv = new BigInteger(1, hinv).modPow(da, na);

        // Enviar (cinv, sighinv) para o professor -> todos os valores em hexadecimal.
        System.out.println("=== Dados a serem enviados para o professor (em hexadecimal) ===\n");
        System.out.println("cinv: " + bigIntegerToHex(cinv) + "\n");
        System.out.println("sighinv: " + bigIntegerToHex(sighinv));
    }

    // Método auxiliar para converter um BigInteger para um array de bytes
    public static byte[] bigIntegerToByteArray(BigInteger b) {
        byte[] data = b.toByteArray();
        // Se o primeiro byte for 0, remover
        if (data[0] == 0) {
            byte[] tmp = new byte[data.length - 1];
            System.arraycopy(data, 1, tmp, 0, tmp.length);
            return tmp;
        }
        return data;
    }

    // Método auxiliar para calcular o hash SHA-256
    public static byte[] sha256Hash(BigInteger s) {
        byte[] sBytes = bigIntegerToByteArray(s);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(sBytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    // Método para decifrar a mensagem usando AES
    public static String decryptAES(BigInteger c, BigInteger s) throws Exception {
        byte[] cBytes = bigIntegerToByteArray(c);
        byte[] sBytes = bigIntegerToByteArray(s);

        // Verificar o comprimento da chave AES
        if (sBytes.length != 16) {
            throw new IllegalArgumentException("Chave AES deve ter 16 bytes (128 bits)");
        }

        // Extrair IV dos primeiros 16 bytes de cHex
        byte[] ivBytes = new byte[16];
        System.arraycopy(cBytes, 0, ivBytes, 0, 16);

        // Extrair a mensagem cifrada dos bytes restantes
        byte[] cipherTextBytes = new byte[cBytes.length - 16];
        System.arraycopy(cBytes, 16, cipherTextBytes, 0, cipherTextBytes.length);

        // Verificar se o comprimento da mensagem cifrada é múltiplo de 16 bytes
        if (cipherTextBytes.length % 16 != 0) {
            throw new IllegalArgumentException("Comprimento da mensagem cifrada inválido");
        }

        // Configurar o AES para decifrar com CBC e padding PKCS5
        SecretKeySpec secretKeySpec = new SecretKeySpec(sBytes, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] decryptedBytes = cipher.doFinal(cipherTextBytes);

        // Converter os bytes decifrados para uma string
        return new String(decryptedBytes, "UTF-8");
    }

    // Método para cifrar a mensagem usando AES
    public static byte[] encryptAES(String minv, BigInteger s, byte[] iv) throws Exception {
        byte[] sBytes = bigIntegerToByteArray(s);
        
        SecretKeySpec secretKeySpec = new SecretKeySpec(sBytes, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        return cipher.doFinal(minv.getBytes("UTF-8"));
    }

    // Método auxiliar para inverter uma string
    public static String reverseString(String s) {
        return new StringBuilder(s).reverse().toString();
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
