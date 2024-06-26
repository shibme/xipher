import React, { useRef, useEffect, useState } from 'react'
import { MdKeyboardArrowDown, MdKeyboardArrowUp } from "react-icons/md";
import { Button, Col, Overlay, Tooltip, OverlayTrigger, Form, InputGroup, Spinner } from 'react-bootstrap';
import { FaEye, FaEyeSlash } from 'react-icons/fa';
import { FaGithub } from "react-icons/fa6";
import { GrUpdate, GrPowerReset } from "react-icons/gr";

export default function TopNav({ page, handleReGenerateURL, username, setUsername}) {
    const popupRef = useRef(null);
    const nameRef = useRef(null);
    const passwordRef = useRef(null);
    const updateUserRef = useRef(null);
    const updatePassRef = useRef(null);
    const nameBtnRef = useRef(null);
    const passBtnRef = useRef(null);
    const [showPopup, setShowPopup] = useState({
        parent: false,
        child: false
    });
    const [isUpdated, setIsUpdated] = useState(false);
    const [showPassword, setShowPassword] = useState(false);
    const [regenText, setRegenText] = useState('Update');
    const [isLoading, setIsLoading] = useState(false);

    const updateUserDetails = (type, callback) => {
        return new Promise((resolve) => {
            if (type === 'user') {
                let userName = nameRef.current.value || 'User'
                localStorage.setItem('username', userName);
                setUsername(userName);
                if(callback) {
                    callback(userName);
                }
            } else {
                localStorage.setItem('xipherSecret', passwordRef.current.value);
            }
            setIsUpdated(false);
            resolve();
        });
    };

    const handleNameUpdate = async () => {
        setTimeout(async () => {
            await updateUserDetails('user', async (updatedUsername) => {
                if(page === 'decrypt') await handleReGenerateURL('username',updatedUsername);
            });
        }, 0);
    }

    const handleRegenerate = async (page) => {
        setRegenText('loading');
        setTimeout(async () => {
            await updateUserDetails('password');
            if (page === 'decrypt') await handleReGenerateURL('password');
            setRegenText('Update');
        }, 0);
    };

    const resetPassword = () => {
        setIsLoading(true);
        setTimeout(async () => {
            await handleReGenerateURL('xipherSecret');
            setIsLoading(false);
            passwordRef.current.value = localStorage.getItem('xipherSecret');
        }, 1000);
    }

    useEffect(() => {
        function handleClickOutside(event) {
            if ((updateUserRef.current && updateUserRef.current.contains(event.target)) || (updatePassRef.current && updatePassRef.current.contains(event.target)) || (nameRef.current && nameRef.current.contains(event.target)) || (passwordRef.current && passwordRef.current.contains(event.target)) || (nameBtnRef.current && nameBtnRef.current.contains(event.target)) || (passBtnRef.current && passBtnRef.current.contains(event.target))) {
                return;
            }
            if (popupRef.current && !popupRef.current.contains(event.target)) {
                setShowPopup(prevState => ({ ...prevState, parent: false, child: false }));
            }
        }
        document.addEventListener("mousedown", handleClickOutside);
        return () => {
            document.removeEventListener("mousedown", handleClickOutside);
        };
    }, [popupRef, updateUserRef, updatePassRef, nameRef, passwordRef, nameBtnRef, passBtnRef]);

    return (
        <Col className='d-flex justify-content-between align-items-center'>
            <div className='d-flex align-items-center gap-2 mt-2 justify-content-center'>
                <img src='./xipher.svg' className='xipher-logo' alt='xipher' />
                <h2 className='text-center mb-0'>Xipher</h2>
            </div>
            <div className='d-flex justify-content-end mt-2 gap-3 align-items-center'>
            <OverlayTrigger placement='bottom' overlay={<Tooltip id='tooltip'>shibme/xipher</Tooltip>} >
                <a className='color-black' href='https://github.com/shibme/xipher' target='_blank' rel='noopener noreferrer'>
                    <FaGithub className='github-link' />
                </a>
            </OverlayTrigger>
            <Button variant='secondary' size='md' className="arrow-container color-black mt-2" ref={popupRef} onClick={() => setShowPopup(prevState => ({ ...prevState, parent: !showPopup.parent }))}>
                {showPopup.parent ? <MdKeyboardArrowUp /> : <MdKeyboardArrowDown />}
                <span>Hi <span className={username !== 'User' ? 'bold-500' : ''}>{username}</span>!</span>
            </Button>
            <Overlay target={popupRef.current} show={showPopup.parent} placement="bottom" onHide={() => setShowPopup(prevState => ({ ...prevState, parent: false }))}>
                {(props) => (
                    <Tooltip placement='bottom' id="overlay" {...props}>
                        <div className="popup color-black">
                            <div className="popup-title">Update Info</div>
                            <div className="popup-content">
                                <div className="user-details">
                                    <OverlayTrigger
                                        placement='left'
                                        rootClose={true}
                                        trigger='click'
                                        overlay={
                                            <Tooltip id='tooltip position-relative'>
                                                <div ref={nameBtnRef} className='popupInner'>
                                                    <Form.Control type='text' ref={nameRef} defaultValue={username || 'User'} onChange={() => setIsUpdated(true)} />
                                                    <Button className='color-black fs-14 text-decoration-none' variant="link color-white" onClick={() => {handleNameUpdate()}} disabled={!isUpdated}>Update</Button>
                                                </div>
                                            </Tooltip>
                                        }
                                    >
                                        <Button ref={updateUserRef} className='drop-btn color-black fs-14'
                                            onClick={() => setShowPopup(prevState => ({ ...prevState, child: !showPopup.child }))} variant="link">
                                            User Name
                                        </Button>
                                    </OverlayTrigger>
                                    <OverlayTrigger
                                        placement='left'
                                        trigger='click'
                                        rootClose={true}
                                        overlay={
                                            <Tooltip id='tooltip position-relative'>
                                                <div ref={passBtnRef} className='popupInner'>
                                                    <InputGroup className="mb-3 name-input">
                                                        <Form.Control
                                                            className='fs-14'
                                                            type={showPassword ? 'text' : 'password'}
                                                            ref={passwordRef}
                                                            defaultValue={localStorage.getItem('xipherSecret')}
                                                            placeholder="password"
                                                            aria-label="password"
                                                            aria-describedby="basic-addon2"
                                                        />
                                                        <InputGroup.Text id="basic-addon2" className='cursor-pointer'>{
                                                            showPassword ? <FaEye onClick={() => { setShowPassword(!showPassword); passwordRef.current.type = 'text' }} /> : <FaEyeSlash onClick={() => { setShowPassword(!showPassword); passwordRef.current.type = 'text' }} />
                                                        }</InputGroup.Text>
                                                    </InputGroup>
                                                    <div className='d-flex flex-column'>
                                                        <OverlayTrigger
                                                            placement='bottom'
                                                            overlay={<Tooltip id='tooltip'>Updating password will replace your existing secret</Tooltip>}
                                                        >
                                                            <Button className='d-flex justify-content-center align-items-center gap-2 color-black fs-14 text-decoration-none' variant="link color-white" onClick={() => handleRegenerate(page)}>Update {regenText === 'loading' ?
                                                                <Spinner animation="border" role="status" size="sm">
                                                                    <span className="visually-hidden">Loading...</span>
                                                                </Spinner> : <GrUpdate />}
                                                            </Button>
                                                        </OverlayTrigger>
                                                        <Button className='d-flex  justify-content-center align-items-center gap-2 color-black fs-14 text-decoration-none' variant="link color-white" onClick={resetPassword}>
                                                            Reset {
                                                                isLoading ? <Spinner className='color-black' animation="border" role="status" size="sm">
                                                                    <span className="visually-hidden">Loading...</span>
                                                                </Spinner> : <GrPowerReset className='reset-icon' />
                                                            }
                                                        </Button>
                                                    </div>
                                                </div>
                                            </Tooltip>
                                        }
                                    >
                                        <Button ref={updatePassRef} className='drop-btn color-black fs-14'
                                            onClick={() => setShowPopup(prevState => ({ ...prevState, child: !showPopup.child }))} variant="link">
                                            Password/Key
                                        </Button>
                                    </OverlayTrigger>
                                </div>
                            </div>
                        </div>
                    </Tooltip>
                )}
            </Overlay>
            </div>
        </Col>
    )
}
