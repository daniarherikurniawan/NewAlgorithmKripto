import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;

public class App {
	/*Path to open File*/
//	final static String mainPath = "/media/daniar/myPassport/WorkPlace/Windows/NewAlgorithmKripto/file/";
	final static String mainPath = "file/";
	
	public static void main(String args[]) { 
		/*Key should be per 8 characters length, min 8 and max 32*/
		String key = new String("daniarherikurnia");

		runECB(key);
		runCBC(key);
//		runCFB(key);
		
	} 
	
	public static void runCFB(String key){
		
		/*Mode Encryption*/
			
			/*Read plain text from PlainText.txt*/
			ArrayList<Integer> plainText = readFile(mainPath+"PlainText.txt");
//			System.out.println(cfb.plainText);
			/*Start the CFB mode*/
			/*Create an instance of modeCFB class*/
			modeCFB cfb = new modeCFB(key,plainText);
			cfb.cipherText = cfb.startEncryptionModeCFB(cfb.plainText);
//			System.out.println("cdc"+cfb.cipherText);
			
			/*Write cipher text to ChiperText.txt*/
			writeFile(cfb.cipherText, mainPath+"ChiperTextCFB.txt");
		
		/*Mode Decryption*/
			
			/*Read cipher text from ChiperText.txt*/
			cfb.cipherText = readFile(mainPath+"ChiperTextCFB.txt");
//			System.out.println("cdc"+cfb.cipherText);
			
			/*Start the CFB mode*/
			cfb.resultText = cfb.startDecryptionModeCFB(cfb.cipherText);
//			
			
			/*Write result text to ResultText.txt*/
			writeFile(cfb.resultText, mainPath+"ResultTextCFB.txt");
			
		System.out.println("CFB Success ");
	}
	
	public static void runECB(String key){
		/*Create an instance of modeECB class*/
		modeECB ecb = new modeECB(key);
		
		/*Mode Encryption*/
			
			/*Read plain text from PlainText.txt*/
			ecb.plainText = readFile(mainPath+"PlainText.txt");
			
			/*Start the CFB mode*/
			ecb.cipherText = ecb.startEncryptionModeECB(ecb.plainText);

			/*Write cipher text to ChiperText.txt*/
			writeFile(ecb.cipherText, mainPath+"ChiperTextECB.txt");

		/*Mode Decryption*/
			
			/*Read cipher text from ChiperText.txt*/
			ecb.cipherText = readFile(mainPath+"ChiperTextECB.txt");

			/*Start the CFB mode*/
			ecb.resultText = ecb.startDecryptionModeECB(ecb.cipherText);
			
			/*Write result text to ResultText.txt*/
			writeFile(ecb.resultText, mainPath+"ResultTextECB.txt");
			
		System.out.println("ECB Success");
	}
	
	
	public static void runCBC(String key){
		/*Create an instance of runCBC class*/
		modeCBC cbc = new modeCBC(key);
		
		/*Mode Encryption*/
			
			/*Read plain text from PlainText.txt*/
			cbc.plainText = readFile(mainPath+"PlainText.txt");
			
			/*Start the CFB mode*/
			cbc.cipherText = cbc.startEncryptionModeCBC(cbc.plainText);
			
			/*Write cipher text to ChiperText.txt*/
			writeFile(cbc.cipherText, mainPath+"ChiperTextCBC.txt");
		
		/*Mode Decryption*/
			
			/*Read cipher text from ChiperText.txt*/
			cbc.cipherText = readFile(mainPath+"ChiperTextCBC.txt");
			
			/*Start the CFB mode*/
			cbc.resultText = cbc.startDecryptionModeCBC(cbc.cipherText);
			
			/*Write result text to ResultText.txt*/
			writeFile(cbc.resultText, mainPath+"ResultTextCBC.txt");
			
		System.out.println("CBC Success");
	}
	
	/*This function will read any file and convert the content to array of Integer
	 * the single Integer is between 0 - 255 even though there is a special character*/
	public static ArrayList<Integer> readFile(String path){
		FileInputStream fis = null;
		ArrayList<Integer> myList = new ArrayList<Integer>();
    	try {
			fis = new FileInputStream(path);
			int content;
			while ((content = fis.read()) != -1) {
	            myList.add(content);
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				if (fis != null)
					fis.close();
			} catch (IOException ex) {
				ex.printStackTrace();
			}
		}
		return myList;
	}

	/*This function will write an array of Integer to the desired file*/
	public static void writeFile(ArrayList<Integer> myList, String path){
		BufferedOutputStream bos;
		try {
			bos = new BufferedOutputStream(
			        new FileOutputStream(new File(path)));
			for (int i = 0; i < myList.size(); i++) {
            	bos.write(myList.get(i).intValue());
    		}
	        bos.close();
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
