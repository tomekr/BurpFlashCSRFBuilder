package com.ff7f00.burp.flashcsrf;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import java.awt.Color;
import java.awt.Component;
import java.awt.event.ActionListener;
import java.net.URL;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.swing.BorderFactory;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableCellRenderer;

import net.miginfocom.swing.MigLayout;

public class FlashCSRFGeneratorView extends JFrame {

	/**
	 * DERP
	 */
	private static final long serialVersionUID = 1293316738962758238L;

	// Initialize UI Components
	private JButton m_addBtn = new JButton("Add");
	private JButton m_removeBtn = new JButton("Remove");
	private JButton m_generateBtn = new JButton("Generate");
        
        URL imageURL = this.getClass().getClassLoader().getResource("Open16.gif");
	private JButton m_chooseBtn = new JButton("", new ImageIcon(imageURL));
        
	private JTextField m_destinationTxtField = new JTextField();
	private JTable headersTable;
	private DefaultTableModel tableModel;
	private JTextField m_urlText;
	private JTextArea m_bodyText;
	private JLabel m_preflightRequired = new JLabel();
        private IExtensionHelpers helper;

	private FlashCSRFGeneratorModel m_model;

	/** Constructor */
	public FlashCSRFGeneratorView(FlashCSRFGeneratorModel model) {

		// Set up the logic
		m_model = model;
		
		// Finalize layout
		this.getContentPane().add(createPanel());
		this.pack();

		this.setTitle("Flash CSRF PoC Generator");

		// Set the frame size and center

		this.setSize(700, 600);
		this.setLocationRelativeTo(null);

		this.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
	}

	@SuppressWarnings("serial")
	private JPanel createPanel() {
		MigLayout layout = new MigLayout("fillx", "[right]rel[grow,fill]", "[]10[]");
		JPanel panel = new JPanel(layout);
                
                m_bodyText = new JTextArea();
                m_bodyText.setLineWrap(true);
                
                if (m_model.getBody().length != 0) {
                    byte[] bodyToView = m_model.getBody();
                    String bodyToViewString = m_model.getBurpCallback().getHelpers().bytesToString(bodyToView);
                    m_bodyText.setText(bodyToViewString);   
                }

		JLabel methodText = new JLabel(m_model.getMethod());
		methodText.setBorder(BorderFactory.createLineBorder(Color.black));
		
		tableModel = new DefaultTableModel();
		tableModel.addTableModelListener(new TableModelListener() {

			@Override
			public void tableChanged(TableModelEvent e) {
				checkPreflight();
			}
		});
		
		headersTable = new JTable(tableModel){
			public Component prepareRenderer(TableCellRenderer renderer, int row, int column){
				Component c = super.prepareRenderer(renderer, row, column);

				if (!isRowSelected(row)){
					c.setBackground(getBackground());
					int modelRow = convertRowIndexToModel(row);
					
					// Get header field and value from headers JTable, I don't like that this is here
					String field = (String)getModel().getValueAt(modelRow, ((DefaultTableModel)getModel()).findColumn("Field"));
					String value = (String)getModel().getValueAt(modelRow, ((DefaultTableModel)getModel()).findColumn("Value"));
					
					// Highlight the header row if it is not a simple header row (i.e. will require a pre-flight request)
					if(!FlashCSRFGeneratorModel.isSimpleHeaderRow(field, value)) {
						c.setBackground(Color.YELLOW);
					}
				}

				return c;
			}
		};
		
		ListSelectionModel selectionModel = headersTable.getSelectionModel();  
        selectionModel.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        
		// Add a list selection listener that toggles the Remove button based on
		// whether or not a row is selected in the headersTable
        selectionModel.addListSelectionListener(new ListSelectionListener() {
            public void valueChanged(ListSelectionEvent e) { 
                ListSelectionModel lsm = (ListSelectionModel)e.getSource();
                m_removeBtn.setEnabled(!lsm.isSelectionEmpty());
            }
        });

		// Create the "Field" and "Value" column headers 
		tableModel.addColumn("Field"); 
		tableModel.addColumn("Value"); 
		
		// Add headers rows
		for(String[] row : m_model.getFinalHeadersString()) {
			tableModel.addRow(row);
		}
		
		m_urlText = new JTextField(m_model.getUrl());
		panel.add(new JLabel("URL:"),   "");
		panel.add(m_urlText,          "wrap");
		
		panel.add(new JLabel("Data: "), "");
		panel.add(m_bodyText,          "wrap");
		
		panel.add(new JLabel("Method: "), "");
		panel.add(methodText, "wrap");
		
		panel.add(new JLabel("Headers: "), "");
		panel.add(new JScrollPane(headersTable), "");
		panel.add(m_addBtn, "");
		
		// Initially disabled the remove button as no header rows will be selected.
		m_removeBtn.setEnabled(false);
		panel.add(m_removeBtn, "wrap");
		
		
		panel.add(new JLabel("Destination: "), "");
		panel.add(m_destinationTxtField);
		panel.add(m_chooseBtn, "wrap");
		
		panel.add(new JLabel("Preflight Status: "), "");
		checkPreflight();
		
		m_preflightRequired.setBorder(BorderFactory.createLineBorder(Color.black));
		m_preflightRequired.setOpaque(true);
		panel.add(m_preflightRequired, "wrap");
		
		panel.add(m_generateBtn, "wrap");

		return panel;
	}
	
	void close() {
		setVisible(false);
	    dispose();
	}
	
	void checkPreflight() {
		m_model.setCurrentHeaders(getTableData());
		
		if (m_model.isPreflightRequired()) {
			m_preflightRequired.setText("Required");
			m_preflightRequired.setBackground(Color.YELLOW);
		} else {
			m_preflightRequired.setText("Not Required");
			m_preflightRequired.setBackground(Color.GREEN);
		}
	}

	void updateDestinationTxtField(String text) {
		m_destinationTxtField.setText(text);
	}
	
	void removeTableRows(int[] rows) {
		// Sort the rows first, because if multiple rows are selected, then the
		// idicies will be all screwed up if you don't remove them in the right
		// order.
		Arrays.sort(rows);
		reverse(rows);
		
		// Go through and remove each selected row
		for (int row : rows) {
			tableModel.removeRow(row);
		}
	}
	
	void addBlankTableRow() {
		// Add a blank row the the JTable
		tableModel.addRow(new String[]{"",""});
		
		// Send the focus to the JTable and edit the first cell of the row
		headersTable.requestFocus();
		headersTable.editCellAt(tableModel.getRowCount()-1, 0);
	}
	
	int[] getSelectedRowsFromTable() {
		return headersTable.getSelectedRows();
	}
	
	void showError(String errMessage) {
		JOptionPane.showMessageDialog(this, errMessage);
	}

	void addAddListener(ActionListener cal) {
		m_addBtn.addActionListener(cal);
	}

	void addRemoveListener(ActionListener cal) {
		m_removeBtn.addActionListener(cal);
	}

	void addGenerateListener(ActionListener cal) {
		m_generateBtn.addActionListener(cal);
	}

	void addSaveListener(ActionListener cal) {
		m_chooseBtn.addActionListener(cal);
	}
	
	String getDestinationValue() {
		return m_destinationTxtField.getText();
	}
	

	
	// Helper method to reverse an array (this shouldn't be in the view, sorry
	// Trygve Reenskaug)
	public static void reverse(int[] b) {
		int left = 0; // index of leftmost element
		int right = b.length - 1; // index of rightmost element

		while (left < right) {
			// exchange the left and right elements
			int temp = b[left];
			b[left] = b[right];
			b[right] = temp;

			// move the bounds toward the center
			left++;
			right--;
		}
	}
	
	/*
	 * GETTERS
	 */
	
	public Map<String, String> getTableData() {
		Map<String, String> headers = new HashMap<String, String>();
		int nRow = tableModel.getRowCount();
		
		if(nRow == 0) {
			return headers;
		}
		
		for (int i = 0 ; i < nRow ; i++)
			headers.put((String) tableModel.getValueAt(i,0), (String) tableModel.getValueAt(i,1));
		
	    return headers;
	}
	
	public String getUrlText() {
		return m_urlText.getText();
	}
	
	public String getBodyText() {
		return m_bodyText.getText(); 
	}
}