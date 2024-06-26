import React, { useState } from 'react'
import { Tooltip, OverlayTrigger } from 'react-bootstrap';
import { FaHandPointDown, FaRegCopy, FaShareSquare, FaWhatsapp, FaTelegramPlane } from "react-icons/fa";
import { MdOutlineEmail } from "react-icons/md";
import { PiMicrosoftTeamsLogo } from "react-icons/pi";

export default function URLContainer({ url, title, onCopyURL, copyBtnText, content, contentTitle }) {
    const [loading, setLoading] = useState(false);

    const genericShare = async () => {
        setLoading(true);
        try {
            await navigator.share({
                title: contentTitle,
                text: content
            });
        } catch (error) {
            console.error('Error sharing: ', error);
        } finally {
            setLoading(false);
        }
    };

    return (
        <>
            <h6 className='text-center fs-6'>{title} <FaHandPointDown className='color-yellow' /></h6>
            <div className='d-flex justify-content-center align-items-center mb-5 w-100 p-0 url-copy-container'>
                <p className='m-2 fs-14'>{url}</p>
                <div className='m-2 d-flex gap-3'>
                    <OverlayTrigger
                        placement="top"
                        overlay={
                            <Tooltip id={`tooltip-top`}>{copyBtnText}</Tooltip>
                        }
                    >
                        <span className='cursor-pointer' onClick={onCopyURL} ><FaRegCopy /></span>
                    </OverlayTrigger>
                    {
                        navigator.share ? <span className='cursor-pointer' onClick={genericShare}><FaShareSquare />{
                            loading ? <div id="loading-bar-spinner" className="spinner"><div className="spinner-icon"></div></div> : null
                        }</span>
                            :
                            <OverlayTrigger
                                placement="top"
                                trigger="click"
                                rootClose={true}
                                overlay={
                                    <Tooltip id='tooltip-top' className='white-tooltip'>
                                        <div className='d-flex'>
                                            <span className='fw-500'>Share :</span>
                                            <span className='social-sharing d-flex ms-2 align-items-center gap-2'>
                                                <FaWhatsapp onClick={() => window.open(`https://wa.me/?text=${encodeURIComponent(contentTitle + ': ' + content)}`, '_blank')} className='whatsapp cursor-pointer' />
                                                <FaTelegramPlane onClick={() => window.open(`https://telegram.me/share/url?url=${contentTitle}&text=${encodeURIComponent(content)}`, '_blank')} className='telegram cursor-pointer' />
                                                <PiMicrosoftTeamsLogo onClick={() => window.open(`https://teams.microsoft.com/share?msgText=${encodeURIComponent(contentTitle + ': ' + content)}&preview=false&s=1675706704556`, '_blank')} className='teams cursor-pointer' />
                                                <MdOutlineEmail onClick={() => window.open(`mailto:?subject=${encodeURIComponent(contentTitle)}&body=${encodeURIComponent(content)}`, '_blank')} className='mail cursor-pointer' />
                                            </span>
                                        </div>
                                    </Tooltip>
                                }
                            >
                                <span className='cursor-pointer'><FaShareSquare /></span>
                            </OverlayTrigger>
                    }
                </div>
            </div>
        </>
    )
}
