#include <jni.h>
#include <string>

//字段声明
const char HexCode[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E',
                        'F'};
const char *ClassName = "com/sharker/ndkdemo/JNIUtils";//指定要注册的类 即nativie方法所在的类

// region  HSA1

//HSA1
int HSA1Size = 41;                      //HSA1 总长度
char *absolute = "119C31AE97";
const char *abbreviate = "D9BC8C4A40";
const char *abacus = "53DC8C0B4C";
const char *car = "649C3C7B76";
// end HSA1

//private_key
int privateKeySize = 861;             //私钥 总长度
char *suit = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAOUKjAjHBLauE26Ld9Wuin/dbQ+2WCuzQIuwXZDl7BybtqIkuYz3/u03YtT/UdIuk9WFdn2NDs5vQ8OF";
const char *daughter = "gekqZSkE+a8/uILydB0vXS2uPrEHiVm0GD+UHHLmSGi9Zxi6Umoe7MCZMSic6PgENkRRxqIBl0ouHFRynN/Sdh0CYBfFAgMBAAECgYBS0heE7QJFVHjuVjxE5lJqnhTb";
const char *meet = "w6HqW20RlfqfdKSGS8AkrYby9JIYERkJ0DE0AWevpA0OpT0fZJhqURKCz7O4DEVyAzu+Dhdexw0SwMIhnckjhPVGMvWNRbz0ZkUbFW+4ObHTp/p3YDei1K6Z1lVYbUyL";
const char *letter = "WVboo19LmJ7a9yaV2QJBAPkeSS2YXFN0X6ITd7r8jd/L+xyhkKmMF9IMCrOsi10Y12dvf0iv6Jaq13JPnSNQAttvCF5VwegqTUc32vTARzsCQQDrXkeqOpTq3G2brbkr";
const char *cake = "1TMqY5X2+Lvrie/AiOm+3z6sEz/H3Y53/3P6PamFl5gRwkZdx7fSCpuBAb1YQAM0ISz/AkBuOg5bFF1Vt9pQ1phVrkYATjtQEdT2kDxB/n4FvkTz7nfxFo6VVPBvKiym";
const char *knife = "Mb/vzglVmq1zQDLKTV1gM8C4JxPdAkAVPyGBAGDJArTyRLBegJRp0yuKa9Gq5Xy7CKDxFf32UpaDWECwHGM/x6kx4glcMQlhFdJGJ6b58kpBWSXw4r3JAkEAzwU37mYh";
const char *pencil = "dtti+yY6qNLf5hKCwA/pKo7aJ4vPG7aJmc9ACWEtHWLUNaF1aRhZd48cd1DCrIlYYjbpgoa/84FNYQ==";
//end private_key

//endregion

//region 常用方法

//jstring转char*
char *jStringToString(JNIEnv *env, jstring jstr) {
    char *rtn = NULL;
    jclass clsstring = env->FindClass("java/lang/String");
    jstring strencode = env->NewStringUTF("utf-8");
    jmethodID mid = env->GetMethodID(clsstring, "getBytes", "(Ljava/lang/String;)[B");
    jbyteArray barr = (jbyteArray) env->CallObjectMethod(jstr, mid, strencode);
    jsize alen = env->GetArrayLength(barr);
    jbyte *ba = env->GetByteArrayElements(barr, JNI_FALSE);
    if (alen > 0) {
        rtn = (char *) malloc(alen + 1);
        memcpy(rtn, ba, alen);
        rtn[alen] = 0;
    }
    env->ReleaseByteArrayElements(barr, ba, 0);
    return rtn;
}

//char 转 jstring
jstring charToJstring(JNIEnv *env, char *str) {
    jsize len = strlen(str);

    jclass clsstring = env->FindClass("java/lang/String");
    jstring strencode = env->NewStringUTF("GB2312");

    jmethodID mid = env->GetMethodID(clsstring, "<init>", "([BLjava/lang/String;)V");
    jbyteArray barr = env->NewByteArray(len);

    env->SetByteArrayRegion(barr, 0, len, (jbyte *) str);
    return (jstring) env->NewObject(clsstring, mid, barr, strencode);
}

//获取应用的上下文对象
jobject getApplication(JNIEnv *env) {
    jclass localClass = env->FindClass("android/app/ActivityThread");
    if (localClass != NULL) {
        jmethodID getapplication = env->GetStaticMethodID(localClass, "currentApplication",
                                                          "()Landroid/app/Application;");
        if (getapplication != NULL) {
            jobject application = env->CallStaticObjectMethod(localClass, getapplication);
            return application;
        }
        return NULL;
    }
    return NULL;
}

/****
 * 获取 设定的 hsa1
 */
char *getSpecifyHSA(JNIEnv *env) {
    char mCodes[HSA1Size];
    strcpy(mCodes, absolute);
    strcat(mCodes, abbreviate);
    strcat(mCodes, abacus);
    strcat(mCodes, car);
    return jStringToString(env, env->NewStringUTF(mCodes));
}

/****
 * 获取私key
 */
jstring getPrivateKeyString(JNIEnv *env) {
    char mCodes[privateKeySize];
    strcpy(mCodes, suit);
    strcat(mCodes, daughter);
    strcat(mCodes, meet);
    strcat(mCodes, letter);
    strcat(mCodes, cake);
    strcat(mCodes, knife);
    strcat(mCodes, pencil);
    return charToJstring(env, mCodes);
}

/****
 * 获取签名
 * type = 1 时 获取 sha1
 * type = 2 时 获取 md5
 */
jstring getSign(JNIEnv *env, int type) {
    //获取到Context
    jobject context = getApplication(env);
    jclass activity = env->GetObjectClass(context);
    // 得到 getPackageManager 方法的 ID
    jmethodID methodID_func = env->GetMethodID(activity, "getPackageManager",
                                               "()Landroid/content/pm/PackageManager;");
    // 获得PackageManager对象
    jobject packageManager = env->CallObjectMethod(context, methodID_func);
    jclass packageManagerclass = env->GetObjectClass(packageManager);
    //得到 getPackageName 方法的 ID
    jmethodID methodID_pack = env->GetMethodID(activity, "getPackageName", "()Ljava/lang/String;");
    //获取包名
    jstring name_str = (jstring) (env->CallObjectMethod(context, methodID_pack));
    // 得到 getPackageInfo 方法的 ID
    jmethodID methodID_pm = env->GetMethodID(packageManagerclass, "getPackageInfo",
                                             "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    // 获得应用包的信息
    jobject package_info = env->CallObjectMethod(packageManager, methodID_pm, name_str, 64);
    // 获得 PackageInfo 类
    jclass package_infoclass = env->GetObjectClass(package_info);
    // 获得签名数组属性的 ID
    jfieldID fieldID_signatures = env->GetFieldID(package_infoclass, "signatures",
                                                  "[Landroid/content/pm/Signature;");
    // 得到签名数组，待修改
    jobject signatur = env->GetObjectField(package_info, fieldID_signatures);
    jobjectArray signatures = (jobjectArray) (signatur);
    // 得到签名
    jobject signature = env->GetObjectArrayElement(signatures, 0);
    // 获得 Signature 类，待修改
    jclass signature_clazz = env->GetObjectClass(signature);
    //---获得签名byte数组
    jmethodID tobyte_methodId = env->GetMethodID(signature_clazz, "toByteArray", "()[B");
    jbyteArray signature_byte = (jbyteArray) env->CallObjectMethod(signature, tobyte_methodId);
    //把byte数组转成流
    jclass byte_array_input_class = env->FindClass("java/io/ByteArrayInputStream");
    jmethodID init_methodId = env->GetMethodID(byte_array_input_class, "<init>", "([B)V");
    jobject byte_array_input = env->NewObject(byte_array_input_class, init_methodId,
                                              signature_byte);
    //实例化X.509
    jclass certificate_factory_class = env->FindClass("java/security/cert/CertificateFactory");
    jmethodID certificate_methodId = env->GetStaticMethodID(certificate_factory_class,
                                                            "getInstance",
                                                            "(Ljava/lang/String;)Ljava/security/cert/CertificateFactory;");
    jstring x_509_jstring = env->NewStringUTF("X.509");
    jobject cert_factory = env->CallStaticObjectMethod(certificate_factory_class,
                                                       certificate_methodId, x_509_jstring);
    //certFactory.generateCertificate(byteIn);
    jmethodID certificate_factory_methodId = env->GetMethodID(certificate_factory_class,
                                                              "generateCertificate",
                                                              ("(Ljava/io/InputStream;)Ljava/security/cert/Certificate;"));
    jobject x509_cert = env->CallObjectMethod(cert_factory, certificate_factory_methodId,
                                              byte_array_input);

    jclass x509_cert_class = env->GetObjectClass(x509_cert);
    jmethodID x509_cert_methodId = env->GetMethodID(x509_cert_class, "getEncoded", "()[B");
    jbyteArray cert_byte = (jbyteArray) env->CallObjectMethod(x509_cert, x509_cert_methodId);

    //MessageDigest.getInstance("SHA1")
    jclass message_digest_class = env->FindClass("java/security/MessageDigest");
    jmethodID methodId = env->GetStaticMethodID(message_digest_class, "getInstance",
                                                "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    jstring sha1_jstring;
    if (type == 1) {
        sha1_jstring = env->NewStringUTF("SHA1");
    } else {
        sha1_jstring = env->NewStringUTF("MD5");
    }
    jobject sha1_digest = env->CallStaticObjectMethod(message_digest_class, methodId, sha1_jstring);
    //sha1.digest (certByte)
    methodId = env->GetMethodID(message_digest_class, "digest", "([B)[B");
    jbyteArray sha1_byte = (jbyteArray) env->CallObjectMethod(sha1_digest, methodId, cert_byte);
    //toHexString
    jsize array_size = env->GetArrayLength(sha1_byte);
    jbyte *sha1 = env->GetByteArrayElements(sha1_byte, NULL);
    char hex_sha[array_size * 2 + 1];
    int i;
    for (i = 0; i < array_size; ++i) {
        hex_sha[2 * i] = HexCode[((unsigned char) sha1[i]) / 16];
        hex_sha[2 * i + 1] = HexCode[((unsigned char) sha1[i]) % 16];
    }
    hex_sha[array_size * 2] = '\0';
    return charToJstring(env, hex_sha);
}

/****
 * 获取 SHA1
 */
jstring getSHA1(JNIEnv *env) {
    return getSign(env, 1);
}

/****
 * 获取MD5
 */
jstring getMD5(JNIEnv *env) {
    return getSign(env, 2);
}
//endregion

// region 获取私钥  外部访问方法
/****
 * 提供俱外部访问的方法
 * 主要是用来获取 私钥 的
 * 已做了验证的，签名需要一样才会返回 私钥
 * 不一样时 则会返回 failure
 */
static jstring getKey(JNIEnv *env, jobject obj) {
    char *sha1 = jStringToString(env, getSHA1(env));
    if (strcmp(getSpecifyHSA(env), sha1) != 0) {
        return env->NewStringUTF("获取密钥失败");
    } else {
        return getPrivateKeyString(env);
    }
}
// endregion

//region 动态注册方法
/****
 * 声明需要动态注册的方法
 */
static JNINativeMethod gMethods[] = {
        {"getKey", "()Ljava/lang/String;", (jstring *) getKey}//对应java中的public native void verifySign();
};

/****
 * 注册方法
 */
static int registerNativeMethods(JNIEnv *env, const char *className, JNINativeMethod *gMethods,
                                 int numMethods) {
    jclass clazz;
    clazz = env->FindClass(className);
    if (clazz == NULL) {
        return JNI_FALSE;
    }
    if (env->RegisterNatives(clazz, gMethods, numMethods) < 0) {
        return JNI_FALSE;
    }
    return JNI_TRUE;
}

/****
 * 注册类
 */
static int registerNatives(JNIEnv *env) {
    return registerNativeMethods(env, ClassName, gMethods, sizeof(gMethods) / sizeof(gMethods[0]));
}
// endregion

//region  初始化默认函数
/****
 * 默认函数
 * 在调用 System.loadLibrary 时会调用，不需要手动调用
 */
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = NULL;
    jint result = -1;

    if (vm->GetEnv((void **) &env, JNI_VERSION_1_4) != JNI_OK) {
        return -1;
    }
    if (!registerNatives(env)) {//注册
        return -1;
    }
    //成功
    result = JNI_VERSION_1_4;
    return result;
}
//endregion