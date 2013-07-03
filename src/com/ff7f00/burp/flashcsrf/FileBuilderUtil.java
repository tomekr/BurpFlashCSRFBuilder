package com.ff7f00.burp.flashcsrf;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.nio.channels.FileChannel;
import java.util.ArrayList;
import java.util.List;
import java.io.OutputStream;

public class FileBuilderUtil {
	private static final String FRAGMENT_REPLACEMENT_STRING = "__REPLACEME__FRAGMENT__REPLACEME__";

	public static void replaceFragment(String replacementText, String outputDirectory) throws IOException {
                // Create references to resource files
		InputStream templateHtmlFile = getResourcePath("csrf_payload.html");
		
		// Create files to be used for PoC
		File outputHtmlFile = new File(outputDirectory + "/csrf_poc.html");
                
		inputStreamtoFile(getResourcePath("csrf.swf"), outputDirectory + "/csrf.swf");
		
		// We need to store all the lines
		List<String> lines = new ArrayList<String>();

		// first, read the file and store the changes
		BufferedReader in = new BufferedReader(new InputStreamReader(templateHtmlFile));
		String line = in.readLine();
		while (line != null) {
			if (line.contains(FRAGMENT_REPLACEMENT_STRING)) {
				line = line.replaceAll(FRAGMENT_REPLACEMENT_STRING, replacementText);
			}
			lines.add(line);
			line = in.readLine();
		}
		in.close();

		// now, write the file again with the changes
		PrintWriter out = new PrintWriter(outputHtmlFile);
		for (String l : lines)
			out.println(l);
		out.close();
                
                templateHtmlFile.close();	
	}
        
        public static void inputStreamtoFile(InputStream inputStream, String destination) {
            OutputStream outputStream = null;
 
            try {
                    // write the inputStream to a FileOutputStream
                    outputStream = 
                        new FileOutputStream(new File(destination));

                    int read = 0;
                    byte[] bytes = new byte[1024];

                    while ((read = inputStream.read(bytes)) != -1) {
                            outputStream.write(bytes, 0, read);
                    }

                    System.out.println("Done!");

            } catch (IOException e) {
                    e.printStackTrace();
            } finally {
                    if (inputStream != null) {
                            try {
                                    inputStream.close();
                            } catch (IOException e) {
                                    e.printStackTrace();
                            }
                    }
                    if (outputStream != null) {
                            try {
                                    // outputStream.flush();
                                    outputStream.close();
                            } catch (IOException e) {
                                    e.printStackTrace();
                            }

                    }
            }
        }
        
        public static InputStream getResourcePath(String filename) {
            return FileBuilderUtil.class.getClassLoader().getResourceAsStream(filename);
        }
}