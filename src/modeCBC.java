import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.HashMap;
import java.util.Map;

public class modeCBC {
	/*Initialization Vector*/
	ArrayList<Integer> IV;

	int  blockSize = 16;
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
	
	/*Constructor of modeCBC*/
	public modeCBC(String key){
		/*initialization*/
		this.key = key;
		this.blockSize = key.length();
		this.plainText = new ArrayList<Integer>();
		this.cipherText = new ArrayList<Integer>();
		this.resultText = new ArrayList<Integer>();
		this.IV = new ArrayList<Integer>();
		
		/*set Initialization Vector from sha-256 of the key*/
		MessageDigest md;
		try {
			md = MessageDigest.getInstance("SHA-256");
			md.update(key.getBytes("UTF-8"));
			byte[] bytesIV = md.digest();
			for (int i = 0; i < bytesIV.length; i++) {
				BitSet bitsetKey = BitSet.valueOf(new byte[] { bytesIV[i] });
				this.IV.add(commonOperation.bitSetToInt(bitsetKey));
			}
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	

	
	public ArrayList<Integer> encrypt(String key, ArrayList<Integer>  plainText){
		ArrayList<Integer> result = new ArrayList<Integer>();
	
		ArrayList<Integer> constant = IV;
		
		int i = 0;
		for (i = 0 ; i < plainText.size()-blockSize ; i += blockSize){
	
			ArrayList<Integer> singleBlock = new ArrayList<Integer>();
			
			/*XOR before doing encription*/
			ArrayList<Integer> arrayInput= new ArrayList<Integer>();
			
			/*one single block = 8 Bytes*/
			for (int j = 0; j < blockSize; j++) {
				arrayInput.add(plainText.get(i+j));
			}
			singleBlock = commonOperation.XOR( arrayInput, constant);
	
			/*Encription per block*/
			singleBlock = newAlgorithm.blockE(key, singleBlock);	
			
			/*Save the result (cipher)*/
			result.addAll(singleBlock);	
			
			/*Update the constant as CBC rules*/
			constant = singleBlock;
			
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
	
			singleBlock = commonOperation.XOR( singleBlock, constant);
			/*Encription per block*/
			singleBlock = newAlgorithm.blockE(key, singleBlock);
			result.addAll(singleBlock);		
		}
	
		return result;
	}

	public ArrayList<Integer> decrypt(String key, ArrayList<Integer>  plainText){

		
		ArrayList<Integer> result = new ArrayList<Integer>();
		
		ArrayList<Integer> constant = IV;
		
		int i = 0 ;
		for (i = 0 ; i < plainText.size()-blockSize ; i += blockSize){

			ArrayList<Integer> singleBlock = new ArrayList<Integer>();
			
			ArrayList<Integer> arrayInput= new ArrayList<Integer>();
			/*one single block = 4 Bytes*/
			for (int j = 0; j < blockSize; j++) {
				arrayInput.add(plainText.get(i+j));
			}

			
			/*Decription per block*/
			singleBlock = newAlgorithm.blockD(key, arrayInput);	

			/*XOR after doing encription*/
			singleBlock = commonOperation.XOR( singleBlock, constant);
			

			/*Update the constant as CBC rules*/
			constant = arrayInput;
			
			/*Save the result (cipher)*/
			result.addAll(singleBlock);	
			
		}

		/*The remaining 1 byte*/
		if(i <  plainText.size()){
			ArrayList<Integer> arrayInput = new ArrayList<Integer>();
			for (int j = i; j < plainText.size(); j++) {
				arrayInput.add(plainText.get(j));
			}
			ArrayList<Integer> singleBlock= new ArrayList<Integer>();

			/*Decription per block*/
			singleBlock = newAlgorithm.blockD(key, arrayInput);

			singleBlock = commonOperation.XOR( singleBlock, constant);
			
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
	
		
	/*Start the encryption mode CBC*/
	public ArrayList<Integer> startEncryptionModeCBC(ArrayList<Integer> plainText){

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
	

	/*Start the decryption mode CBC*/
	public ArrayList<Integer> startDecryptionModeCBC(ArrayList<Integer> plainText){

		ArrayList<Integer> result = new ArrayList<Integer>();
		result = (ArrayList<Integer>) plainText.clone();
		String subKey = "";
		for (int i = 0; i < iterate; i++) {
			subKey = commonOperation.getSubKey(key, iterate-i-1);
			result = decrypt(subKey, result);
		}
		return result;
	}
	
}
