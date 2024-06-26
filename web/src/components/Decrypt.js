import React, { useCallback, useEffect, useState } from 'react'
import xipher from '../xipher';
import { IoLockOpen } from "react-icons/io5";
import URLContainer from './URLContainer';
import { Button, Col, Form, Row } from 'react-bootstrap';
import { MdOutlineErrorOutline } from "react-icons/md";

const useClipboard = (initialText) => {
    const [copyBtnText, setCopyBtnText] = useState(initialText);

    const copyToClipboard = (text) => {
        navigator.clipboard.writeText(text)
            .then(() => {
                setCopyBtnText('Copied');
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

export default function Decrypt({ pKey: publicKey, secretURL, setSecretURL, cipherText, requester }) {
    const [text, setText] = useState(cipherText || '');
    const [isDecrypted, setIsDecrypted] = useState(false);
    const [decryptedText, setDecryptedText] = useState();
    const [error, setError] = useState(null);
    const [copyBtnText, copyToClipboard] = useClipboard('Copy');
    const [isLoading, setIsLoading] = useState(false);

    const onDecryptText = useCallback(async () => {
        setIsLoading(true);
        try {
            if (!text) return alert('Please enter encrypted text to decrypt');
            let encryptedData;
            try {
                let url = new URL(text);
                let params = new URLSearchParams(url.search);
                let ct = params.get('ct');
                encryptedData = ct;
            } catch (err) {
                encryptedData = text;
            }
            let xSecret = localStorage.getItem('xipherSecret');
            let decryptedText = await xipher.decryptStr(xSecret, encryptedData);
            setDecryptedText(decryptedText);
            setIsDecrypted(true);
        } catch (err) {
            if (err.message.includes('password required')) {
                setError('Decryption failed: Please ensure you are using the right browser or set the password using the option from the top right corner.');
            } else if (err.message.includes('decrypter failed')) {
                setError('Decryption failed: Please ensure you are using the right browser.');
            } else {
                setError(err.message);
            }
        } finally {
            setIsLoading(false);
        }
    }, [text])

    useEffect(() => {
        let current_url = window.location.href.includes('/?') ? window.location.href.split('/?')[0] : window.location.href;
        setSecretURL((current_url.endsWith('/') ? current_url.slice(0, -1) : current_url) + '?pk=' + publicKey + (localStorage.getItem('username') && localStorage.getItem('username').toLowerCase() !== 'user' ? '&u=' + localStorage.getItem('username') : ''));
    }, [publicKey, setSecretURL])

    useEffect(() => {
        if (cipherText) {
            setIsDecrypted(false);
            onDecryptText();
        }
    }, [cipherText, onDecryptText])

    return (
        <Row className='col-lg-6 mx-auto'>
            <Col className='main-container align-items-center justify-content-center d-flex flex-column'>
                {secretURL && !cipherText ? (
                    <URLContainer page="decrypt" content={secretURL} contentTitle={"Encryption URL"} title={"Share this URL with someone to receive a secret"} url={secretURL} copyBtnText={copyBtnText} onCopyURL={() => copyToClipboard(secretURL)} />
                ) : null}
                {
                    !cipherText ? <div className="w-100 d-flex align-items-center justify-content-center gap-2 mb-5">
                        <Form.Control as={"input"} placeholder={"Enter encrypted data or url"} value={text} id="text" className='fs-14' onChange={(e) => setText(e.target.value)} />
                        <Button className='w-25 h-60' onClick={() => {
                            setIsDecrypted(false);
                            setIsLoading(true);
                            setTimeout(() => {
                                onDecryptText();
                                setIsLoading(false);
                            }, 0);
                        }}>Decrypt <IoLockOpen /></Button>
                    </div> : null
                }
                {
                    isLoading ? <div className='position-relative'><div id="loading-bar-spinner" className="spinner"><div className="spinner-icon"></div></div></div> : null
                }
                {
                    isDecrypted ? (
                        <div className='d-flex flex-column gap-3 decryptBox mb-5 align-items-center justify-content-center text-center'>
                            {
                                requester ? <h6>The below decrypted secret was shared with you by <b>{requester}</b></h6> : <h6>The decrypted secret shared with you is displayed below</h6>
                            }
                            <Form.Control as={"textarea"} placeholder={"Decrypted text"} value={decryptedText} id="decryptedText" className='w-80 fs-14' readOnly />
                            <Button className='copyText' onClick={() => copyToClipboard(decryptedText)}>{copyBtnText}</Button>
                        </div>
                    ) : error ? <div className="d-flex flex-column justify-content-center align-items-center gap-4 color-red error p-3 text-center ">
                        <MdOutlineErrorOutline />
                        <p>{error}</p>
                    </div> : null
                }
            </Col>
        </Row>
    )
}