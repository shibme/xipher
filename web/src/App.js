import React, { useEffect, useState, useCallback, useMemo } from 'react'
import { useLocation } from 'react-router-dom';
import Encrypt from './components/Encrypt';
import Decrypt from './components/Decrypt';
import xipher from './xipher';
import { Container, Row, Col } from 'react-bootstrap';
import TopNav from './components/TopNav';

const reGenerateURL = async (type, setPublicKey, publicKey, setSecretURL, url, username) => {
   let public_key = publicKey
   if(type === 'password') {
    public_key = await xipher.getPublicKey(localStorage.getItem('xipherSecret'));
    setPublicKey(public_key);
   } else if (type === 'xipherSecret') {
    let xSecret = await xipher.newSecretKey();
    localStorage.setItem('xipherSecret', xSecret);
    public_key = await xipher.getPublicKey(xSecret);
    setPublicKey(public_key);
   }
   const urlSuffix = username && username.toLowerCase() !== 'user' ? `&u=${username}` : '';
   setSecretURL(`${url}?pk=${publicKey}${urlSuffix}`);
}

export default function App() {
    const location = useLocation();
    const [publicKey, setPublicKey] = useState('');
    const [requester, setRequester] = useState('');
    const [page, setPage] = useState('');
    const [secretURL, setSecretURL] = useState('');
    const [cipherText, setCipherText] = useState('');
    const [username, setUsername] = useState(localStorage.getItem('username') || 'User');

    useEffect(() => {
        const fetchPageDetails = async () => {
            let xSecret = localStorage.getItem('xipherSecret');
            if (!xSecret) {
                xSecret = await xipher.newSecretKey();
                localStorage.setItem('xipherSecret', xSecret);
            }
    
            let public_key = await xipher.getPublicKey(xSecret);
            setPublicKey(public_key);

            if (location.search) {
                const searchParams = new URLSearchParams(location.search);
                const pKey = searchParams.get('pk');
                const user = searchParams.get('u');
                const ct = searchParams.get('ct');
                if (user) setRequester(user);
                if (pKey) {
                    setPublicKey(pKey);
                    setPage('encrypt');
                    return
                }
                if(ct) setCipherText(ct);
            }
            setPage('decrypt');
        }
        fetchPageDetails();
    }, [location.search])

    const url = useMemo(() => window.location.href.endsWith('/') ? window.location.href.slice(0, -1) : window.location.href, []);

    const handleReGenerateURL = useCallback((type, username) => reGenerateURL(type, setPublicKey, publicKey, setSecretURL, url, username), [publicKey, url]);


    return (
        <Container fluid>
            <Row>
                <TopNav username={username} setUsername={setUsername} setPublicKey={setPublicKey} page={page} handleReGenerateURL={handleReGenerateURL} />
            </Row>
            <Row>
                <Col>
                    <p className='text-center mt-6 mb-5'>Xipher web is a fully client-side encryption tool that allows users securely share secrets<br/> without having the need to install any software.</p>
                </Col>
            </Row>
            {
                {
                    'decrypt': <Decrypt requester={requester} cipherText={cipherText} secretURL={secretURL} setSecretURL={setSecretURL} pKey={publicKey} page={page} />,
                    'encrypt': <Encrypt username={username} page={page} requester={requester} pKey={publicKey} />,
                    '': <div id="loading-bar-spinner" className="spinner"><div className="spinner-icon"></div></div>
                }[page]
            }
        </Container>
    );
}