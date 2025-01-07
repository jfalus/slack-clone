function showNewGroupForm() {
    document.getElementById('newGroupDialog').style.display = 'block';
}

function hideNewGroupForm() {
    document.getElementById('newGroupDialog').style.display = 'none';
}

var quill = new Quill('#editor-container', {
    theme: 'snow',
    placeholder: 'Type your message...',
    modules: {
        toolbar: [
            ['bold', 'italic', 'underline', 'strike'],
            ['blockquote', 'code-block'],
            [{ 'list': 'ordered'}, { 'list': 'bullet' }],
            [{ 'color': [] }, { 'background': [] }],
            ['clean']
        ]
    }
});

function prepareSubmit(e) {
    e.preventDefault();
    var content = quill.root.innerHTML;
    if (content.trim() === '<p><br></p>' || content.trim() === '') {
        return; // Don't submit empty messages
    }
    document.getElementById('hiddenContent').value = content;
    document.getElementById('messageForm').submit();
}

function scrollToBottom() {
    var messages = document.querySelector('.messages');
    messages.scrollTop = messages.scrollHeight;
}

scrollToBottom();

quill.keyboard.addBinding({
    key: 13,
    ctrlKey: true
}, function(range, context) {
    prepareSubmit(new Event('submit'));
});