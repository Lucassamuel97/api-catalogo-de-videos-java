package com.fullcycle.catalogo.domain.exceptions;

import com.fullcycle.catalogo.domain.validation.handler.Notification;

public class NotificationException extends DomainException {

    protected NotificationException(final String aMessage, final Notification notification) {
        super(aMessage, notification.getErrors());
    }

    public static NotificationException with(final String message, final Notification notification) {
        return new NotificationException(message, notification);
    }
}