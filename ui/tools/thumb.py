import wx
import os
import wx.lib.agw.thumbnailctrl
from wx.lib.agw.scrolledthumbnail import THUMB_OUTLINE_FULL, THUMB_OUTLINE_RECT, THUMB_OUTLINE_NONE


def draw_thumb_nail(self, bmp, thumb, index):
    """
    Draws a visible thumbnail.

    :param `bmp`: the thumbnail version of the original image;
    :param `thumb`: an instance of :class:`Thumb`;
    :param `index`: the index of the thumbnail to draw.
    """

    dc = wx.MemoryDC()
    dc.SelectObject(bmp)

    x = self._tBorder/2
    y = self._tBorder/2

    # background
    dc.SetPen(wx.Pen(wx.BLACK, 0, wx.TRANSPARENT))
    dc.SetBrush(wx.Brush(self.GetBackgroundColour(), wx.BRUSHSTYLE_SOLID))
    dc.DrawRectangle(0, 0, bmp.GetWidth(), bmp.GetHeight())

    # image
    if index == self.GetPointed() and self.GetHighlightPointed():
        factor = 1.5
        img = thumb.GetHighlightBitmap(self._tWidth, self._tHeight, factor)
    else:
        img = thumb.GetBitmap(self._tWidth, self._tHeight)

    ww = img.GetWidth()
    hh = img.GetHeight()
    imgRect = wx.Rect(int(x + (self._tWidth - img.GetWidth())/2),
                      int(y + (self._tHeight - img.GetHeight())/2),
                      img.GetWidth(), img.GetHeight())

    if not thumb._alpha and self._dropShadow:
        dc.Blit(imgRect.x+5, imgRect.y+5, imgRect.width, imgRect.height, self.shadow, 500-ww, 500-hh)
    dc.DrawBitmap(img, imgRect.x, imgRect.y, True)

    colour = self.GetSelectionColour()
    selected = self.IsSelected(index)

    colour = self.GetSelectionColour()

    # draw caption
    sw, sh = 0, 0
    if self._showfilenames:
        textWidth = 0
        dc.SetFont(self.GetCaptionFont())
        mycaption = thumb.GetCaption(0)
        sw, sh = dc.GetTextExtent(mycaption)

        if sw > self._tWidth:
            mycaption = self.CalculateBestCaption(dc, mycaption, sw, self._tWidth)
            sw = self._tWidth

        textWidth = sw + 8
        tx = x + (self._tWidth - textWidth)/2
        ty = y + self._tHeight

        txtcolour = "#7D7D7D"
        dc.SetTextForeground(txtcolour)

        tx = x + (self._tWidth - sw)/2
        if hh >= self._tHeight:
            ty = y + self._tHeight + (self._tTextHeight - sh)/2 + 3
        else:
            ty = y + hh + (self._tHeight-hh)/2 + (self._tTextHeight - sh)/2 + 3

        dc.DrawText(mycaption, int(tx), int(ty))

    # outline
    if self._tOutline != THUMB_OUTLINE_NONE and (self._tOutlineNotSelected or self.IsSelected(index)):

        dotrect = wx.Rect()
        dotrect.x = int(x - 2)
        dotrect.y = int(y - 2)
        dotrect.width = bmp.GetWidth() - self._tBorder + 4
        dotrect.height = bmp.GetHeight() - self._tBorder + 4

        dc.SetPen(wx.Pen((self.IsSelected(index) and [colour] or [wx.LIGHT_GREY])[0],
                         0, wx.PENSTYLE_SOLID))
        dc.SetBrush(wx.Brush(wx.BLACK, wx.BRUSHSTYLE_TRANSPARENT))

        if self._tOutline == THUMB_OUTLINE_FULL or self._tOutline == THUMB_OUTLINE_RECT:

            imgRect.x = int(x)
            imgRect.y = int(y)
            imgRect.width = bmp.GetWidth() - self._tBorder
            imgRect.height = bmp.GetHeight() - self._tBorder

            if self._tOutline == THUMB_OUTLINE_RECT:
                imgRect.height = self._tHeight

        dc.SetBrush(wx.TRANSPARENT_BRUSH)

        if selected:

            dc.SetPen(self.grayPen)
            dc.DrawRoundedRectangle(dotrect, 2)

            dc.SetPen(wx.Pen(wx.WHITE))
            dc.DrawRectangle(int(imgRect.x), int(imgRect.y),
                             imgRect.width, imgRect.height)

            pen = wx.Pen((selected and [colour] or [wx.LIGHT_GREY])[0], 1)
            pen.SetJoin(wx.JOIN_MITER)
            dc.SetPen(pen)
            if self._tOutline == THUMB_OUTLINE_FULL:
                dc.DrawRoundedRectangle(imgRect.x - 1, imgRect.y - 1,
                                        imgRect.width + 2, imgRect.height + 2, 1)
            else:
                dc.DrawRectangle(int(imgRect.x - 1), int(imgRect.y - 1),
                                 imgRect.width + 3, imgRect.height + 3)

    dc.SelectObject(wx.NullBitmap)


wx.lib.agw.scrolledthumbnail.ScrolledThumbnail.DrawThumbnail = draw_thumb_nail


# remove extension of the icon file
def get_caption(self, line):
    if line + 1 >= len(self._captionbreaks):
        return ""
    strs = self._caption
    return strs.split('.')[0]

wx.lib.agw.scrolledthumbnail.Thumb.GetCaption = get_caption


def list_directory(self, directory, fileExtList):
    """
    Returns list of file info objects for files of particular extensions.

    :param `directory`: the folder containing the images to thumbnail;
    :param `fileExtList`: a Python list of file extensions to consider.
    """

    lSplitExt = os.path.splitext
    return [f for f in os.listdir(directory) if lSplitExt(f)[1].lower() in fileExtList and self.keyword in f.lower()]

wx.lib.agw.thumbnailctrl.ThumbnailCtrl.ListDirectory = list_directory


# for python3.10
def scroll_t0_selected(self):
    """ Scrolls the :class:`ScrolledWindow` to the selected thumbnail. """

    if self.GetSelection() == -1:
        return

    # get row
    row = self.GetSelection() // self._cols
    # calc position to scroll view

    paintRect = self.GetPaintRect()
    y1 = row * (self._tHeight + self._tBorder) + self.GetCaptionHeight(0, row)
    y2 = y1 + self._tBorder + self._tHeight + self.GetCaptionHeight(row)

    if y1 < paintRect.GetTop():
        sy = y1  # scroll top
    elif y2 > paintRect.GetBottom():
        sy = y2 - paintRect.height  # scroll bottom
    else:
        return

    # scroll view
    xu, yu = self.GetScrollPixelsPerUnit()
    sy = sy / yu + (sy % yu and [1] or [0])[0]  # convert sy to scroll units
    x, y = self.GetViewStart()

    self.Scroll(int(x), int(sy))

wx.lib.agw.scrolledthumbnail.ScrolledThumbnail.ScrollToSelected = scroll_t0_selected
