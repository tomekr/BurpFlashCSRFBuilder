package burp;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.LinkedList;
import java.util.List;

import javax.swing.JMenuItem;

// MVC yo...
import com.ff7f00.burp.flashcsrf.FlashCSRFGeneratorModel;
import com.ff7f00.burp.flashcsrf.FlashCSRFGeneratorView;
import com.ff7f00.burp.flashcsrf.FlashCSRFGeneratorController;

public class BurpExtender implements IBurpExtender, IContextMenuFactory
{
	private IBurpExtenderCallbacks burpCallback;
	private FlashCSRFGeneratorModel model;
	private FlashCSRFGeneratorView view;
	private FlashCSRFGeneratorController controller;
    //
    // implement IBurpExtender
    //
	
	final public static String MENU_ITEM_TEXT = "Generate Flash CSRF PoC";
	
	public void registerExtenderCallbacks(IBurpExtenderCallbacks burpCallback) {
		this.burpCallback = burpCallback;

		burpCallback.registerContextMenuFactory(this);
	}
		
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		// Get the selected request(s)
		final IHttpRequestResponse requests[] = invocation.getSelectedMessages();
		
		// Only show the "Generate Flash CSRF PoC" menu item if one request was selected
		if(requests.length == 1)
		{
			// Create the LinkedList that will hold the menu item
			List<JMenuItem> ret = new LinkedList<JMenuItem>();
			
			// Create the menu item that will show "Generate Flash CSRF PoC"
			JMenuItem menuItem = new JMenuItem(MENU_ITEM_TEXT);
			menuItem.addActionListener(new ActionListener(){
				public void actionPerformed(ActionEvent arg0) {
					if(arg0.getActionCommand().equals(MENU_ITEM_TEXT)){
				        
                                            // Setup the MVC architecture for the generator
                                            model      = new FlashCSRFGeneratorModel(requests[0], burpCallback);
                                            view       = new FlashCSRFGeneratorView(model);
                                            controller = new FlashCSRFGeneratorController(model, view);

                                            // Show the Container
                                            view.setVisible(true);
					}
				}
			});
			
			// Add the items to the linked list and return it
			ret.add(menuItem);
			return(ret);
		}
		
		return null;
	}
}
