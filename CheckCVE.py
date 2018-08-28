from tkinter import *
from tkinter import ttk
import requests
import json
from urllib.parse import urljoin

class App:
    
    selectedCpeItem = 'default'
    baseUrl = 'https://cve.circl.lu'
    
    def initSession(self):
        self.session = requests.Session()
        self.session = requests.Session()
        self.session.headers.update({
            'content-type': 'application/json',
            'User-Agent': 'PyCveMonitor'})

    def matchCpeSelectAndApiSyntax(self, cpeItem):
        if cpeItem == 'FortiOs':
            self.selectedCpeItem = 'fortios'
        if cpeItem == 'FortiMail':
            self.selectedCpeItem = 'fortimail'
        if cpeItem == 'FortiWeb':
            self.selectedCpeItem = 'fortiweb'
        if cpeItem == 'FortiAnalyzer':
            self.selectedCpeItem = 'fortianalyzer_firmware'
        if cpeItem == 'FSSO':
            self.selectedCpeItem = 'single_sign_on'
        return self.selectedCpeItem

    def checkCve(self, cpeItem):
        resultWindows = Toplevel(self.rootWindows)
        

        
        subframe = ttk.Frame(resultWindows, padding=(10, 10, 10, 10))
        subframe.grid(column=0, row=0, sticky=(N, S, E, W))

        Grid.rowconfigure(resultWindows, 0, weight=1)
        Grid.columnconfigure(resultWindows, 0, weight=1)
        
        tree = ttk.Treeview(subframe, show='headings')
        tree['columns'] = ('cveid', 'publication', 'references', 'summary')
        tree.grid(column=0, row=0, sticky=(N, S, E, W))
        
        tree.column('cveid', width=100, anchor='center')
        tree.heading('cveid', text='ID')
        
        tree.column('publication', width=100, anchor='center')
        tree.heading('publication', text='DATE')
        
        tree.column('references', width=300, anchor='center')
        tree.heading('references', text='REFEREENCES')
        
        tree.column('summary', width=800, anchor='center')
        tree.heading('summary', text='DESCRIPTION')

        
        
        
        self.matchCpeSelectAndApiSyntax(cpeItem)

        self.initSession()

        url = urljoin(self.baseUrl, 'api/{}/{}'.format('cvefor', '/cpe:/o:fortinet:' + self.selectedCpeItem ))

        response = self.session.get(url)

        parsed_json = ''
        if response.status_code == 200:
            parsed_json = response.json()

        for item in parsed_json:
            # le mot clé "end" permet d'insérer à la fin
            # '' -> on laisse au TreeView la tache de créer un id pour le nouveau noeud

            tree.insert('', 'end', values=(item['id'], item['nessus'][0]['published'], item['references'], item['summary']))
                                                           
        #messagebox.showinfo("TEST", "Ceci est un test")

    def __init__(self, rootWindows):

        self.rootWindows = rootWindows
        Grid.rowconfigure(self.rootWindows, 0, weight=1)
        Grid.columnconfigure(self.rootWindows, 0, weight=1)

        # attention de ne pas faire de confusion entre l'instance Tk() et l'instance Ttk()
        # Ttk fait référecence au nouveau "themed widgets" qui ont été ajoutés à Tk dans la version 8.5
        
        self.rootWindows.title('FORTINET CVE CHECK')
        
        mainframe = ttk.Frame(self.rootWindows, padding=(10, 10, 10, 10))
        

        # Sticky: permet de définir le postionnement du widget à l'intérieur d'une cellule
        # Padding: permet de définir l'espace entre les widgets
        # Il y a plusieurs moyens pour gérer la gestion du positionnement des éléments, pack, paned windows, canevas.
        # Ici nous utilisons l'élément Grid pour sa simplicité d'utilisation.
        mainframe.grid(column=4, row=5, sticky=(N, S, E, W))
        
        mainframe.columnconfigure(0, weight=1, minsize=100)
        mainframe.columnconfigure(1, weight=1, minsize=100)
        mainframe.columnconfigure(2, weight=1, minsize=100)
        mainframe.columnconfigure(3, weight=1, minsize=100)
        mainframe.columnconfigure(4, weight=1, minsize=100)

        mainframe.rowconfigure(0, weight=1, minsize=30)
        mainframe.rowconfigure(1, weight=1, minsize=30)
        mainframe.rowconfigure(2, weight=1, minsize=30)
        mainframe.rowconfigure(3, weight=1, minsize=30)
        mainframe.rowconfigure(4, weight=1, minsize=30)
        mainframe.rowconfigure(5, weight=1, minsize=10)

        label = Label(mainframe, text="Type de produit:")
        label.grid(column=0, row=0, sticky=(N, S, W))

        CpeDisplay = ('FortiOs', 'FortiMail', 'FortiWeb', 'FortiAnalyzer', 'FSSO')

        # l'objet StringVar de l'instance Tk() est utilisé dans l'instance Ttk() où se trouve la combobox
        # pour conserver la persistance de cette valeur, il faut définir la variable comme globale

        global CpeSelect
        CpeSelect = StringVar()
        CpeSelect.set(CpeDisplay[0])
        
        
        Combobox = ttk.Combobox(mainframe, textvariable = CpeSelect, values = CpeDisplay, state = 'readonly')
        Combobox.grid(column=1, row=0)
        Combobox.current(0)
        

        # lambda function ou fonction anonyme
        # pour fournir un paramètre à la fonction, il est nécessaire de passer par une lambda function
        bouton = ttk.Button(mainframe, text="Rechercher", command= lambda x=CpeSelect:self.checkCve(x.get()))
        bouton.grid(column=4, row=4, sticky=(W, E))



if __name__ == '__main__':
    rootWindows = Tk()
    app = App(rootWindows)
    rootWindows.mainloop()

