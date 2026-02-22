# Read the file
with open('server.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Add the send_to_clipboard function after app = Flask(__name__)
old_app = 'app = Flask(__name__)\n\n# Configure the app'
new_app = '''app = Flask(__name__)

# Helper function for clipboard operations
def send_to_clipboard(clip_type, data):
    win32clipboard.OpenClipboard()
    win32clipboard.EmptyClipboard()
    win32clipboard.SetClipboardData(clip_type, data)
    win32clipboard.CloseClipboard()

# Configure the app'''

content = content.replace(old_app, new_app)

# Also fix the image section - remove extra gui.press('enter') after Ctrl+W
old_image_close = '''# Close tab and open new chat
                    gui.keyDown('ctrl')
                    gui.press('w')
                    gui.keyUp('ctrl')
                    time.sleep(1)
                    gui.press('enter')
                    
                    if i == num_count - 1:  # Last element
                        time.sleep(2)
                    else:
                        time.sleep(8)

            is_sending_messages = False
            return render_template('send.html', success='Messages sent successfully!')'''

new_image_close = '''# Close tab with Ctrl+W (no extra Enter needed)
                    gui.keyDown('ctrl')
                    gui.press('w')
                    gui.keyUp('ctrl')
                    time.sleep(2)
                    
                    if i == num_count - 1:  # Last element
                        time.sleep(2)
                    else:
                        time.sleep(8)

            is_sending_messages = False
            return render_template('send.html', success='Messages sent successfully!')'''

content = content.replace(old_image_close, new_image_close)

# Write the file
with open('server.py', 'w', encoding='utf-8') as f:
    f.write(content)

print('File updated successfully!')
