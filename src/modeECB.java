import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class modeECB {
	int  blockSize = 16; /*Bytes*/
	final int  iterate = 3;
	
	/*Key with minimum 8 Byte length or 8 characters*
	 * 1 character = 8 bit = 1 Byte*/	
	String key;
	
	/*Plain text that will be encrypted */
	ArrayList<Integer> plainText;
	/*Chiper text that will be decrypted */
	ArrayList<Integer> cipherText;
	/*Result text is the result of decrypted cipher text */
	ArrayList<Integer> resultText;
	
	/*Constructor of modeCFB*/
	public modeECB(String key){
		/*initialization*/
		this.key = key;
		this.blockSize = key.length();
		this.plainText = new ArrayList<Integer>();
		this.cipherText = new ArrayList<Integer>();
		this.resultText = new ArrayList<Integer>();
	}
	

	
	public ArrayList<Integer> encrypt(String key, ArrayList<Integer>  plainText){
		ArrayList<Integer> result = new ArrayList<Integer>();
		int i = 0;
		for (i = 0 ; i < plainText.size()-blockSize ; i += blockSize){
			
			/*adjust the size of block to be sent for encryption
			 * in this case we assume that one block is one Byte*/
			ArrayList<Integer> singleBlock = new ArrayList<Integer>();
			
			/*one single block = 8 Bytes*/
			for (int j = 0; j < blockSize; j++) {
				singleBlock.add(plainText.get(i+j));
			}
//			System.out.println(key);
			singleBlock = newAlgorithm.blockE(key, singleBlock);
			singleBlock = commonOperation.shiftLeft(singleBlock);
			/*shift left*/
			result.addAll(singleBlock);	
		}

		/*The remaining byte + padding NUL*/
		if(i <  plainText.size()){

			ArrayList<Integer> singleBlock= new ArrayList<Integer>();
			for (int j = i; j - i <= blockSize - 1; j++) {
				if (j < plainText.size() )
					singleBlock.add(plainText.get(j));
				else
					singleBlock.add(0);
			}
			
			/*Encription per block*/
			singleBlock = newAlgorithm.blockE(key, singleBlock);
			singleBlock = commonOperation.shiftLeft(singleBlock);
			result.addAll(singleBlock);		
		}
		return result;
	}

	public ArrayList<Integer> decrypt(String key, ArrayList<Integer>  cipherText){
		ArrayList<Integer> result = new ArrayList<Integer>();
		
		int i = 0;
		for (i = 0 ; i < cipherText.size()-blockSize ; i += blockSize){

			ArrayList<Integer> singleBlock = new ArrayList<Integer>();
			/*one single block = 8 Bytes*/
			for (int j = 0; j < blockSize; j++) {
				singleBlock.add(cipherText.get(i+j));
			}

			/*shift right*/
			singleBlock = (commonOperation.shiftRight(singleBlock));	

			/*ECB 8-bit -> this part will decrypt per character*/
			result.addAll(newAlgorithm.blockD(key, singleBlock));			
		}

		/*The remaining 1 byte + padding NUL*/
		if(i <  cipherText.size()){

			ArrayList<Integer> singleBlock= new ArrayList<Integer>();
			for (int j = i; j < cipherText.size(); j++) {
				singleBlock.add(cipherText.get(j));
			}	
			singleBlock = (commonOperation.shiftRight(singleBlock));
			
			/*Decryption per block*/
			singleBlock = newAlgorithm.blockD(key, singleBlock);
			
			/*remove Padding*/
			boolean findEndOfPadding = false;
			for (int j = singleBlock.size() - 1 ; j >= 0 ; j--) {
				if(!findEndOfPadding && singleBlock.get(j) == 0){
					singleBlock.remove(j);
				}else{
					findEndOfPadding = true;
				}
			}
			result.addAll(singleBlock);	
		}
		return result;
	}
	
	
	/*Start the encryption mode CFB*/
	public ArrayList<Integer> startEncryptionModeECB(ArrayList<Integer> plainText){
		ArrayList<Integer> result = new ArrayList<Integer>();
		result = (ArrayList<Integer>) plainText.clone();
		String subKey = "";
		for (int i = 0; i < iterate; i++) {
			subKey = commonOperation.getSubKey(key, i);
			result = encrypt(subKey, result);
		}
		
		Map<Integer, Integer> frequency = new HashMap<Integer, Integer>();
		frequency = commonOperation.countFrequency(result);
		
		return result;
	}
	
	/*Start the decryption mode CFB*/
	public ArrayList<Integer> startDecryptionModeECB(ArrayList<Integer> cipherText){

		ArrayList<Integer> result = new ArrayList<Integer>();
		result = (ArrayList<Integer>) cipherText.clone();
		/*Iterate 3 times and generate 3 subKey*/
		String subKey = "";
		for (int i = 0; i < iterate; i++) {
			subKey = commonOperation.getSubKey(key, iterate-i-1);
			result = decrypt(subKey, result);
		}
		return result;
	}
	
	
}
