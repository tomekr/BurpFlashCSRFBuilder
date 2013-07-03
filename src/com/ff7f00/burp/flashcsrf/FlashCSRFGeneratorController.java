package com.ff7f00.burp.flashcsrf;

import burp.IExtensionHelpers;
import java.awt.event.*;
import java.io.File;
import java.io.IOException;

import javax.swing.JFileChooser;
import javax.swing.JOptionPane;

public class FlashCSRFGeneratorController {
	// The Controller needs to interact with both the Model and View.
	private FlashCSRFGeneratorModel m_model;
	private FlashCSRFGeneratorView m_view;

	private static final String DESTINATION_ERROR = "You have not selected a Destination folder to save the PoC files in. Please select a folder.";
	private static final String GENERATE_CONFIRMATION = "Files successfully saved";
	private static final String ERROR_SAVING = "An error occurred while attempting to create files";
	// ========================================================== constructor
	/** Constructor */
	public FlashCSRFGeneratorController(FlashCSRFGeneratorModel model, FlashCSRFGeneratorView view) {
		m_model = model;
		m_view = view;

		// Add listeners to the view.
		view.addAddListener(new AddListener());
		view.addRemoveListener(new RemoveListener());
		view.addGenerateListener(new GenerateListener());
		view.addSaveListener(new SaveListener());
	}

	/**
	 * 1. Adds a header field/value row to the headers table TODO
	 */
	class AddListener implements ActionListener {
		public void actionPerformed(ActionEvent e) {
			m_view.addBlankTableRow();
		}
	}

	/**
	 * 1. Removes the selected header from the headers table. TODO
	 */
	class RemoveListener implements ActionListener {
		public void actionPerformed(ActionEvent e) {
			m_view.removeTableRows(m_view.getSelectedRowsFromTable());
		}
	}

	/**
	 * 1. Use the FileBuilderUtil to generate the csrf_poc files.
	 */
	class GenerateListener implements ActionListener {
		public void actionPerformed(ActionEvent e) {
			if (m_view.getDestinationValue().equals("")) {
				JOptionPane.showMessageDialog(null, DESTINATION_ERROR);
			} else {
				// Call the FileBuilderUtil to generate the PoC, sending the
				// destination and request parameters.
				try {
					m_model.setCurrentHeaders(m_view.getTableData());
					m_model.setUrl(m_view.getUrlText());
                                        
                                        if (!"".equals(m_view.getBodyText())) {
                                            m_model.setBody(m_model.getBurpCallback().getHelpers().stringToBytes(m_view.getBodyText()));
                                        }
					
					FileBuilderUtil.replaceFragment(
							m_model.createFragmentForGenerator(),
							m_view.getDestinationValue());
					m_view.close();
					
					// Show confirmation message
					JOptionPane.showMessageDialog(null, GENERATE_CONFIRMATION);
				} catch (IOException exception) {
					JOptionPane.showMessageDialog(null, ERROR_SAVING);
					System.out.println(exception.toString());
				}
			}
		}
	}

	/**
	 * 1. Allow the user to choose a destination to save the poc files in.
	 */
	class SaveListener implements ActionListener {
		public void actionPerformed(ActionEvent e) {
			// Open file chooser dialog
			JFileChooser fileChooser = new JFileChooser();
			fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
			int returnValue = fileChooser.showOpenDialog(null);
			if (returnValue == JFileChooser.APPROVE_OPTION) {
				File selectedFile = fileChooser.getSelectedFile();
				m_view.updateDestinationTxtField(selectedFile.getPath());
			}
		}
	}
}