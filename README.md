<h1 align="center">PyDeskLink</h1>
<p align="center"><b>Remote Administration Tool for Secure Communication</b></p>

---

<h2>Features</h2>
<ul>
  <li><b>Secure Communication:</b> Utilizes AES encryption to ensure secure data transmission between the client and server.</li>
  <li><b>System Information Retrieval:</b> Gather detailed system information from the client machine.</li>
  <li><b>Remote Command Execution:</b> Execute system commands on the client from the server.</li>
  <li><b>File Management:</b> Remotely browse directories, transfer files, and copy files from the client machine.</li>
  <li><b>Keylogging:</b> Capture and store keystrokes on the client machine.</li>
  <li><b>Clipboard Monitoring:</b> Track clipboard activity and store clipboard history.</li>
  <li><b>Audio & Video Capture:</b> Record audio from the microphone, capture video from the webcam, and take screenshots of the client machine.</li>
  <li><b>Graphical User Interface:</b> The server features a PyQt-based GUI for easier management and interaction.</li>
</ul>

<h2>Installation</h2>

<h3>Prerequisites</h3>
<ul>
  <li><b>Python 3.x</b></li>
  <li><b>pip</b> (Python package installer)</li>
</ul>

<h3>Python Libraries</h3>
<p>Install the required libraries using <code>pip</code>:</p>
<pre><code>pip install -r requirements.txt</code></pre>

<p><b>requirements.txt:</b></p>
<pre><code>requests
pyautogui
numpy
opencv-python
pycryptodome
pynput
pyaudio
pyperclip
pyqt5
qdarkstyle</code></pre>

<h3>Setting Up</h3>
<ol>
  <li><b>Clone the Repository:</b>
    <pre><code>git clone https://github.com/yourusername/PyDeskLink.git
cd PyDeskLink</code></pre>
  </li>
  <li><b>Start the Server:</b>
    <p>Run the server script to start listening for incoming connections:</p>
    <pre><code>python server.py</code></pre>
  </li>
  <li><b>Start the Client:</b>
    <p>Run the client script on the target machine:</p>
    <pre><code>python client.py</code></pre>
    <p>Ensure the server IP and port range are correctly configured in the <code>client.py</code> file.</p>
  </li>
</ol>

<h2>Usage</h2>
<p>Once both the server and client are running:</p>
<ul>
  <li><b>System Information:</b> The server can request detailed system info from the client.</li>
  <li><b>Command Execution:</b> Execute terminal commands remotely via the server's command interface.</li>
  <li><b>File Management:</b> Transfer, browse, and manage files remotely.</li>
  <li><b>Keystroke Logging:</b> The client will log all keystrokes and can send the data to the server on request.</li>
  <li><b>Clipboard Monitoring:</b> Track and save clipboard history on the client.</li>
  <li><b>Audio/Video Capture:</b> Remotely capture and save audio, video, and screenshots from the client.</li>
</ul>

<h2>Security & Ethics</h2>
<p><b>PyDeskLink</b> is a powerful tool that can be used for both good and malicious purposes. It's crucial that this tool is used responsibly and legally:</p>
<ul>
  <li><b>Always</b> obtain explicit permission before deploying the client on any machine.</li>
  <li><b>Ensure</b> compliance with all relevant laws and regulations in your jurisdiction.</li>
  <li><b>Avoid</b> using this tool in any manner that violates privacy, trust, or security.</li>
</ul>
<p>Unauthorized use of <b>PyDeskLink</b> may result in severe legal consequences.</p>

<h2>Disclaimer</h2>
<p>This software is provided "as-is" without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.</p>
