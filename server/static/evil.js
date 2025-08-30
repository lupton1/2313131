function showSuccessBlock() {
    // Create the div element
    var successBlock = document.createElement('div');
    
    // Set the id and styles for the div
    successBlock.id = 'success-block';
    successBlock.textContent = 'Success! The evil script was executed!';
    successBlock.style.backgroundColor = '#4CAF50';
    successBlock.style.color = 'white';
    successBlock.style.padding = '15px';
    successBlock.style.textAlign = 'center';
    successBlock.style.position = 'fixed';
    successBlock.style.width = '100%';
    successBlock.style.top = '0';
    successBlock.style.left = '0';
    successBlock.style.zIndex = '1000';
    
    // Append the div to the body
    document.body.appendChild(successBlock);
}

// Call the function to show the success block
showSuccessBlock();