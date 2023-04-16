public class AES {
    public static void main(String[] args) {
        String s1 = "This is an AES encryption algorithm program";   // 明文
        String s2 = "aaaaaaaaaaaaabcd";      // 128位密钥
        String key = fillStr(StrToBinstr(PKCS7Padding(s2))).replace(" ","");
        String plaintext = fillStr(StrToBinstr(PKCS7Padding(s1))).replace(" ","");
//        System.out.println(plaintext);
        int groups = plaintext.length()/128;  // 组数
        StringBuilder plainBuild = new StringBuilder();
        StringBuilder cipherBuild = new StringBuilder();
        for (int i=0;i<groups;i++){
            String group = plaintext.substring(i*128,i*128+128);
            String ciphertext = encrypt(group,key);
            cipherBuild.append(ciphertext);
            System.out.println("第"+(i+1)+"组明文加密后："+ciphertext);
            String decrypted = decrypt(ciphertext,key);
            plainBuild.append(decrypted);
            System.out.println("第"+(i+1)+"组密文解密后："+decrypted);
//            System.out.println(group);
        }
        System.out.println("密文："+cipherBuild);
        int id = s1.length()%16;
        if(id == 0){
            plainBuild.delete(plainBuild.length()-16,plainBuild.length());
        }else {
            plainBuild.delete(plainBuild.length()-16+id,plainBuild.length());
        }
        System.out.println("明文："+plainBuild);
    }

    // 解密算法
    public static String decrypt(String ciphertext,String key){
        String[][] stateMatrix = getMatrix(fillStr(StrToBinstr(PKCS7Padding(ciphertext))).replace(" ",""));
        String[][] keyMatrix = getRoundKey(key);
        stateMatrix = addRoundKey(stateMatrix,10,keyMatrix);
        stateMatrix = invShiftRows(stateMatrix);
        stateMatrix = invSubByte(stateMatrix);
        for (int i=9;i>0;i--){
            stateMatrix = addRoundKey(stateMatrix,i,keyMatrix);
            stateMatrix = invMixColumns(stateMatrix);
            stateMatrix = invShiftRows(stateMatrix);
            stateMatrix = invSubByte(stateMatrix);
        }
        stateMatrix = addRoundKey(stateMatrix,0,keyMatrix);
        return getCiphertext(stateMatrix);
    }

    // 加密算法
    public static String encrypt(String group,String key){
        String[][] stateMatrix = getMatrix(group);
        String[][] keyMatrix = getRoundKey(key);
        stateMatrix = addRoundKey(stateMatrix,0,keyMatrix);
        for (int i=1;i<10;i++){
            stateMatrix = subByte(stateMatrix);
            stateMatrix = shiftRows(stateMatrix);
            stateMatrix = mixColumns(stateMatrix);
            stateMatrix = addRoundKey(stateMatrix,i,keyMatrix);
        }
        stateMatrix = subByte(stateMatrix);
        stateMatrix = shiftRows(stateMatrix);
        stateMatrix = addRoundKey(stateMatrix,10,keyMatrix);
//        System.out.println(Arrays.deepToString(mixColumns(stateMatrix)));
        return getCiphertext(stateMatrix);
    }

    // 轮密钥加变换
    public static String[][] addRoundKey(String[][] matrix,int n,String[][] keyMatrix){
        int k=0;
        for (int i=n*4;i<n*4+4;i++){
            for (int j=0;j<4;j++){
                matrix[j][k] = xor(keyMatrix[j][i],matrix[j][k]);
            }
            k++;
        }
        return matrix;
    }

    // 计算轮密钥数组
    public static String[][] getRoundKey(String key){
        String[][] keyMatrix = getMatrix(key);
        String[][] w = new String[4][44];
        for (int i=0;i<4;i++){
            for (int j=0;j<4;j++){
                w[j][i] = keyMatrix[j][i];
            }
        }
        for (int i=4;i<44;i++){
            if(i%4 != 0){
                String[] wt = new String[]{w[0][i-1],w[1][i-1],w[2][i-1],w[3][i-1]};
                String tmp = wt[0];
                for (int j=0;j<3;j++){
                    wt[j] = wt[j+1];
                }
                wt[3] = tmp;
                for(int j=0;j<4;j++){
                    int x = Integer.parseInt(wt[j].substring(0,4),2);
                    int y = Integer.parseInt(wt[j].substring(4,8),2);
                    String t = Integer.toBinaryString(S[x][y]);
                    while (t.length()<8){
                        t="0"+t;
                    }
                    wt[j] = t;
                    if (j==0) {
                        String round = Integer.toBinaryString(ROUND[i/4-1]);
                        while (round.length()<8){
                            round = "0"+round;
                        }
                        w[j][i] = xor(wt[j],round);
                    } else {
                        w[j][i] = xor(wt[j],"00000000");
                    }
                }
            }else {
                for (int j=0;j<4;j++){
                    w[j][i] = xor(w[j][i-4],w[j][i-1]);
                }
            }
        }
        return w;
    }

    // 逆列混合变换
    public static String[][] invMixColumns(String[][] matrix){
        String[][] res = new String[4][4];
        for (int i=0;i<4;i++){
            for (int p=0;p<4;p++){
                String[] tmp = new String[4];
                for (int q=0;q<4;q++){
                    if (INV_X[p][q] == 0x09){
                        tmp[q] = xor(xMul(xMul(xMul(matrix[q][i]))),matrix[q][i]);
                    } else if (INV_X[p][q] == 0x0b){
                        tmp[q] = xor(xor(xMul(matrix[q][i]),xMul(xMul(xMul(matrix[q][i])))),matrix[q][i]);
                    } else if (INV_X[p][q] == 0x0d) {
                        tmp[q] = xor(xor(xMul(xMul(xMul(matrix[q][i]))),matrix[q][i]),xMul(xMul(matrix[q][i])));
                    } else if (INV_X[p][q] == 0x0e) {
                        tmp[q] = xor(xor(xMul(xMul(xMul(matrix[q][i]))),xMul(xMul(matrix[q][i]))),xMul(matrix[q][i]));
                    }
                }
                res[p][i] = xor(xor(xor(tmp[0],tmp[1]),tmp[2]),tmp[3]);
            }
        }
        return res;
    }

    // 列混合变换
    public static String[][] mixColumns(String[][] matrix){
        String[][] res = new String[4][4];
        for (int i=0;i<4;i++){
                for (int p=0;p<4;p++){
                    String[] tmp = new String[4];
                    for (int q=0;q<4;q++){
                        if (X[p][q] == 0x01){
                            tmp[q] = matrix[q][i];
                        } else if (X[p][q] == 0x02){
//                            matrix[q][i];
//                            tmp[q] = matrix[q][i].substring(1)+"0";
                            tmp[q] = xMul(matrix[q][i]);
                        } else if (X[p][q] == 0x03) {
                            tmp[q] = xMul(matrix[q][i]);
                            tmp[q] = xor(tmp[q],matrix[q][i]);
                        }
                    }
                    res[p][i] = xor(xor(xor(tmp[0],tmp[1]),tmp[2]),tmp[3]);
                }
        }
        return res;
    }

    // GF里乘二操作
    public static String xMul(String str){
        String res;
        if (str.charAt(0) == '1') {
            res = str.substring(1)+"0";
            res = xor(res,"00011011");
        } else {
            res = str.substring(1)+"0";
        }
        return res;
    }

    // 字符串异或
    public static String xor(String a,String b){
        StringBuilder builder = new StringBuilder();
        for(int i=0;i<8;i++){
            if(a.charAt(i) == b.charAt(i)){
                builder.append("0");
            }else {
                builder.append("1");
            }
        }
        return new String(builder);
    }

    // 逆行移位变换
    public static String[][] invShiftRows(String[][] matrix){
        String tmp = matrix[1][3];
        for (int j=3;j>0;j--){
            matrix[1][j] = matrix[1][j-1];
        }
        matrix[1][0] = tmp;

        tmp = matrix[2][0];
        matrix[2][0] = matrix[2][2];
        matrix[2][2] = tmp;
        tmp = matrix[2][1];
        matrix[2][1] = matrix[2][3];
        matrix[2][3] = tmp;

        tmp = matrix[3][0];
        for (int j=0;j<3;j++){
            matrix[3][j] = matrix[3][j+1];
        }
        matrix[3][3] = tmp;
        return matrix;
    }

    // 行移位变换
    public static String[][] shiftRows(String[][] matrix){
        String tmp = matrix[1][0];
        for (int j=0;j<3;j++){
            matrix[1][j] = matrix[1][j+1];
        }
        matrix[1][3] = tmp;

        tmp = matrix[2][0];
        matrix[2][0] = matrix[2][2];
        matrix[2][2] = tmp;
        tmp = matrix[2][1];
        matrix[2][1] = matrix[2][3];
        matrix[2][3] = tmp;

        tmp = matrix[3][3];
        for (int j=3;j>0;j--){
            matrix[3][j] = matrix[3][j-1];
        }
        matrix[3][0] = tmp;
        return matrix;
    }

    // 逆字节代换运算
    public static String[][] invSubByte(String[][] matrix){
        for (int i=0;i<4;i++){
            for (int j=0;j<4;j++){
                int x = Integer.parseInt(matrix[j][i].substring(0,4),2);
                int y = Integer.parseInt(matrix[j][i].substring(4,8),2);
                String tmp = Integer.toBinaryString(INV_S[x][y]);
                while(tmp.length()<8){
                    tmp="0"+tmp;
                }
                matrix[j][i] = tmp;
            }
        }
        return matrix;
    }

    // 字节代换运算
    public static String[][] subByte(String[][] matrix){
        for (int i=0;i<4;i++){
            for (int j=0;j<4;j++){
                int x = Integer.parseInt(matrix[j][i].substring(0,4),2);
                int y = Integer.parseInt(matrix[j][i].substring(4,8),2);
                String tmp = Integer.toBinaryString(S[x][y]);
                while(tmp.length()<8){
                    tmp="0"+tmp;
                }
                matrix[j][i] = tmp;
            }
        }
        return matrix;
    }

    // 得到状态矩阵
    public static String[][] getMatrix(String group){
        String[][] stateMatrix = new String[4][4];
        int t = 0;
        for (int j=0;j<4;j++){
            for (int k=0;k<4;k++){
                stateMatrix[k][j] = group.substring(t*8,t*8+8);
                t++;
            }
        }
        return stateMatrix;
    }

    // 状态矩阵得到字符串
    public static String getCiphertext(String[][] matrix){
        StringBuilder builder = new StringBuilder();
        for (int i=0;i<4;i++){
            for (int j=0;j<4;j++){
                builder.append(matrix[j][i]).append(" ");
            }
        }
//        System.out.println(builder);
        return BinstrToStr(new String(builder));
    }

    // 分组补齐
    public static String PKCS7Padding(String input){
        int id = input.length()%16;
        if(id == 0){
            for (int i=0;i<16;i++){
                input += (char)(16);
            }
        }else {
            for (int i=0;i<16-id;i++){
                input += (char)(16-id);
            }
        }
        return input;
    }

    // 二进制码补0
    public static String fillStr(String input){
        String[] tempStr = StrToStrArray(input);
        StringBuilder ouput = new StringBuilder();
        for (int i = 0; i < tempStr.length; i++) {
            StringBuilder builder = new StringBuilder(tempStr[i]);
            while(builder.length()<8){
                builder.insert(0,0);
            }
            ouput.append(builder.append(" "));
        }
        return new String(ouput);
    }

    // 将字符串转换成二进制字符串，以空格相隔
    private static String StrToBinstr(String str) {
        char[] strChar = str.toCharArray();
        String result = "";
        for (int i = 0; i < strChar.length; i++) {
            result += Integer.toBinaryString(strChar[i]) + " ";
        }
        return result;
    }

    // 将二进制字符串转换成Unicode字符串
    private static String BinstrToStr(String binStr) {
        String[] tempStr = StrToStrArray(binStr);
        char[] tempChar = new char[tempStr.length];
        for (int i = 0; i < tempStr.length; i++) {
            tempChar[i] = BinstrToChar(tempStr[i]);
        }
        return String.valueOf(tempChar);
    }

    // 将二进制字符串转换为char
    private static char BinstrToChar(String binStr) {
        int[] temp = BinstrToIntArray(binStr);
        int sum = 0;
        for (int i = 0; i < temp.length; i++) {
            sum += temp[temp.length - 1 - i] << i;
        }
        return (char) sum;
    }

    // 将初始二进制字符串转换成字符串数组，以空格相隔
    private static String[] StrToStrArray(String str) {
        return str.split(" ");
    }

    // 将二进制字符串转换成int数组
    private static int[] BinstrToIntArray(String binStr) {
        char[] temp = binStr.toCharArray();
        int[] result = new int[temp.length];
        for (int i = 0; i < temp.length; i++) {
            result[i] = temp[i] - 48;
        }
        return result;
    }

    // 轮常量
    private static final int[] ROUND = new int[]{0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

    // 混合变换矩阵
    private static final int[][] X = new int[][]{
        {0x02, 0x03, 0x01, 0x01},
        {0x01, 0x02, 0x03, 0x01},
        {0x01, 0x01, 0x02, 0x03},
        {0x03, 0x01, 0x01, 0x02}
    };

    // 逆混合变换矩阵
    private static final int[][] INV_X = new int[][]{
            {0x0e, 0x0b, 0x0d, 0x09},
            {0x09, 0x0e, 0x0b, 0x0d},
            {0x0d, 0x09, 0x0e, 0x0b},
            {0x0b, 0x0d, 0x09, 0x0e}
    };

    // 逆S盒
    private static final int[][] INV_S = new int[][]{
        {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
        {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
        {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
        {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
        {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
        {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
        {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
        {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
        {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
        {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
        {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
        {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
        {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
        {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
        {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
        {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}
    };

    // S盒
    private static final int[][] S = new int[][]{
            {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
            {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
            {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
            {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
            {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
            {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
            {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
            {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
            {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
            {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
            {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
            {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
            {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
            {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
            {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
            {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
    };
}
