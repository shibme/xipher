import React, { useEffect, useState } from 'react';
import xipher from '../xipher';
import { IoLockClosed } from "react-icons/io5";
import URLContainer from './URLContainer';
import { Row, Form } from 'react-bootstrap';
import { MdOutlineErrorOutline } from "react-icons/md";

const useClipboard = (initialText) => {
    const [copyBtnText, setCopyBtnText] = useState(initialText);

    const copyToClipboard = (text, shouldCopy) => {
        navigator.clipboard.writeText(text)
            .then(() => {
                if (shouldCopy) setCopyBtnText('Copied');
                setTimeout(() => {
                    setCopyBtnText(initialText);
                }, 2000);
            })
            .catch(err => {
                console.error('Failed to copy: ', err);
            })
    }

    return [copyBtnText, copyToClipboard];
}

const Encrypt = ({ pKey: publicKey, requester, page, username }) => {
    const [text, setText] = useState('');
    const [isEncrypted, setIsEncrypted] = useState(false);
    const [encryptedText, setEncryptedText] = useState('');
    const [copyBtnText, copyToClipboard] = useClipboard('Copy', false);
    const [isLoading, setIsLoading] = useState(false);
    const [type, setType] = useState('');
    const [error, setError] = useState('');

    const handleTextChange = (e) => {
        setText(e.target.value);
    }

    useEffect(() => {
        if (type === 'url') {
            let copyOfEncryptedText = encryptedText;
            if (copyOfEncryptedText.includes('&u=')) {
                copyOfEncryptedText = copyOfEncryptedText.split('&u=')[0];
            }
            copyOfEncryptedText += (username && username.toLowerCase() !== 'user') ? '&u=' + username : '';
            setEncryptedText(copyOfEncryptedText);
        }
    }, [username, encryptedText, type])

    const handleEncryptText = async () => {
        let encrypted_text = await xipher.encryptStr(publicKey, text);
        if (!encrypted_text) return alert('Failed to encrypt text. Please try again.');
        if (encrypted_text.length < 2000) {
            let url = window.location.origin + window.location.pathname;
            url = url.includes('/?') ? url.split('/?')[0] : url;
            encrypted_text = (url.endsWith('/') ? url.slice(0, -1) : url) + '?ct=' + encrypted_text + (username && username.toLowerCase() !== 'user' ? '&u=' + username : '');
            setType('url')
        } else {
            setType('text')
        }
        setEncryptedText(encrypted_text);
        setIsEncrypted(true);
        copyToClipboard(encrypted_text, false);
        setText('');
    }

    return (
        <Row className='col-lg-6 mx-auto main-container'>
            <p className='text-center'>A secret has been requested{requester ? <span> by <b>{requester}</b></span> : ''}.</p>
            <div className="text-wrapper mb-5">
                <Form.Control as="textarea" className='w-100 fs-14' id="textarea" value={text} placeholder={"Enter the text you wish to encrypt"} onChange={handleTextChange} />
                <button className="button encrypt" onClick={() => {
                    if(text.trim() === '') {
                        setError('Please enter a text to encrypt');
                        setIsEncrypted(false);
                        return;
                    } 
                    setError('');
                    setIsEncrypted(false);
                    setIsLoading(true);
                    setTimeout(() => {
                        handleEncryptText();
                        setIsLoading(false);
                    }, 0);
                }}>Encrypt <IoLockClosed /></button>
            </div>
            {
                error ? <div className="d-flex flex-column justify-content-center align-items-center gap-4 color-red error p-3 text-center ">
                    <MdOutlineErrorOutline />
                    <p>{error}</p>
                </div> : null
            }
            {
                isLoading ? <div className='position-relative'><div id="loading-bar-spinner" className="spinner"><div className="spinner-icon"></div></div></div> : null
            }
            {
                isEncrypted ? <URLContainer page={page} content={encryptedText} contentTitle={"Encrypted Data"} copyBtnText={copyBtnText} onCopyURL={() => copyToClipboard(encryptedText, true)} url={encryptedText} title={type === 'text' ? "Share this encrypted text with the requester" : "Share this url with the requester"} /> : null
            }
        </Row>
    );
}

export default Encrypt;