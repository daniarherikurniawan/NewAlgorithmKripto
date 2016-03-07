import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.BitSet;

import javax.swing.UIDefaults.LazyInputMap;

public class modeCFB {
	/*Path to open File*/
	final static String mainPath = "/media/daniar/myPassport/WorkPlace/Windows/NewAlgorithmKripto/file/";
	
	/*Key with minimum 8 Byte length or 8 characters*
	 * 1 character = 8 bit = 1 Byte*/	
	String key;
	
	/*Plain text that will be encrypted */
	ArrayList<Integer> plainText;
	/*Chiper text that will be decrypted */
	ArrayList<Integer> chiperText;
	/*Result text is the result of decrypted chiper text */
	ArrayList<Integer> resultText;
	
	/*Constructor of modeCFB*/
	public modeCFB(){
		/*initialization*/
		key = new String();
		this.plainText = new ArrayList<Integer>();
		this.chiperText = new ArrayList<Integer>();
		this.resultText = new ArrayList<Integer>();
	}
	
	
	public static void main(String args[]) { 
		
		/*Create an instance of modeCFB class*/
		modeCFB cfb = new modeCFB();
		
		
		/*Mode Encryption*/
			
			/*Read plain text from PlainText.txt*/
			cfb.plainText = readFile(mainPath+"PlainText.txt");
			
			/*Start the CFB mode*/
			cfb.chiperText = cfb.blockE(cfb.plainText);
			
			/*Write chiper text to ChiperText.txt*/
			writeFile(cfb.chiperText, mainPath+"ChiperText.txt");
		
			
		/*Mode Decryption*/
			
			/*Read chiper text from ChiperText.txt*/
			cfb.chiperText = readFile(mainPath+"ChiperText.txt");
			
			/*Start the CFB mode*/
			cfb.resultText = cfb.blockD(cfb.chiperText);
			
			/*Write result text to ResultText.txt*/
			writeFile(cfb.resultText, mainPath+"ResultText.txt");
		
	} 
	
	public ArrayList<Integer> startEncryptionModeCFB(ArrayList<Integer> plainText){
		ArrayList<Integer> result = new ArrayList<Integer>();
		for (int i = 0 ; i < plainText.size() ; i ++){
			result.addAll(blockE(plainText));
		}
		return result;
	}
	
	/*To encrypt*/
	public ArrayList<Integer> blockE(ArrayList<Integer> plainText){
		ArrayList<Integer> chiper = new ArrayList<Integer>();
		BitSet bitsMask = new BitSet(8); 
		bitsMask = intToBitSet(255);
		System.out.println("BitMask : "+bitSetToBinary(bitsMask));
		for (int i = 0 ; i < plainText.size() ; i ++){
			BitSet bits = new BitSet(); 
			bits = intToBitSet(plainText.get(i));
			bits.xor(bitsMask);
			
			chiper.add(bitSetToInt(bits));
		}
		return chiper;
	}

	/*To decrypt*/
	public ArrayList<Integer> blockD(ArrayList<Integer> plainText){
		ArrayList<Integer> chiper = new ArrayList<Integer>();
		BitSet bitsMask = new BitSet(8); 
		bitsMask = intToBitSet(255);
		System.out.println("BitMask : "+bitSetToBinary(bitsMask));
		for (int i = 0 ; i < plainText.size() ; i ++){
			BitSet bits = new BitSet(); 
			bits = intToBitSet(plainText.get(i));
			bits.xor(bitsMask);
			
			chiper.add(bitSetToInt(bits));
		}
		return chiper;
	}

	/*This function will convert String to Hexadecimal */
	public static String stringToHex(String arg) {
	    return String.format("%040x", new BigInteger(1, arg.getBytes(/*YOUR_CHARSET?*/)));
	}
	
	/*This function will give space between two consequence characters as Hexadecimal format*/
	public static String formatHex(String strHex){
		StringBuilder str = new StringBuilder(strHex);
		int idx = str.length() - 2;

		while (idx > 0)
		{
		    str.insert(idx, " ");
		    idx = idx - 2;
		}
		return str.toString();
	}
	
	/*This function will insert space every 8 characters to represent one Byte*/
	public static String formatByte(String strByte){
		StringBuilder str = new StringBuilder(strByte);
		int idx = str.length() - 8;

		while (idx > 0)
		{
		    str.insert(idx, " ");
		    idx = idx - 8;
		}
		return str.toString();
	}
	
	/*This function convert BitSet to Integer*/
	public static int bitSetToInt(BitSet bitSet){
	    int bitInteger = 0;
	    for(int i = 0 ; i < 32; i++)
	        if(bitSet.get(i))
	            bitInteger |= (1 << i);
	    return bitInteger;
	}
	
	/*This function convert BitSet to Binary*/
	public static String bitSetToBinary(BitSet bitSet){
		int in = bitSetToInt(bitSet);
		return (Integer.toBinaryString(in));
	}

	/*This function convert Long to BitSet*/
	public static BitSet intToBitSet(long value) {
	    BitSet bits = new BitSet();
	    int index = 0;
	    while (value != 0L) {
	      if (value % 2L != 0) {
	        bits.set(index);
	      }
	      ++index;
	      value = value >>> 1;
	    }
	    return bits;
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
